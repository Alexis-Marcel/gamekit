package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/time/rate"
)

// Local : comptes intégrés au jeu, nom d'utilisateur et mot de passe, gardés
// dans sa base (LocalStore). La session tient dans un cookie HttpOnly
// SameSite=Lax dont la base ne garde que le SHA-256. Les pages (connexion,
// inscription, compte, administration) sont servies par Mount sous /compte/.
//
// Inscription (SIGNUP) : open, invite (lien donné par un administrateur, par
// défaut) ou closed. Tant qu'il n'existe aucun compte, la première inscription
// est ouverte et ce compte est administrateur : c'est le démarrage d'une
// instance neuve.
type Local struct {
	store  LocalStore
	info   Info
	signup string
	theme  Theme
	log    *slog.Logger
	now    func() time.Time
	pages  *template.Template

	cache   sync.Map // empreinte de session -> cached
	limitMu sync.Mutex
	limits  map[string]*rate.Limiter
}

type cached struct {
	user    *User
	account Account
	until   time.Time
}

const (
	SignupOpen   = "open"
	SignupInvite = "invite"
	SignupClosed = "closed"

	sessionCookie = "gk_session"
	sessionTTL    = 30 * 24 * time.Hour
	inviteTTL     = 7 * 24 * time.Hour
	resetTTL      = 24 * time.Hour
	cacheTTL      = 30 * time.Second
	base          = "/compte"
)

// LocalInfo : les pages de comptes, pour les liens du front.
type LocalInfo struct {
	LoginURL   string `json:"loginUrl"`
	LogoutURL  string `json:"logoutUrl"` // POST
	AccountURL string `json:"accountUrl"`
	Signup     string `json:"signup"` // open, invite, closed
}

func newLocal(c Config, info Info, log *slog.Logger) (*Local, error) {
	if c.LocalStore == nil {
		return nil, errors.New("AUTH_MODE=local : le jeu doit fournir une LocalStore")
	}
	signup := c.Signup
	if signup == "" {
		signup = SignupInvite
	}
	switch signup {
	case SignupOpen, SignupInvite, SignupClosed:
	default:
		return nil, errors.New("SIGNUP : " + signup + " inconnu (open, invite, closed)")
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	info.Local = &LocalInfo{LoginURL: base + "/connexion", LogoutURL: base + "/deconnexion", AccountURL: base + "/", Signup: signup}
	theme := c.Theme
	theme.defaults()
	return &Local{store: c.LocalStore, info: info, signup: signup, theme: theme, log: log, now: time.Now, pages: pages,
		limits: map[string]*rate.Limiter{}}, nil
}

func (l *Local) Info() Info { return l.info }

// User lit la session du cookie. Une requête qui modifie quelque chose et vient
// d'un autre site (Origin) est traitée en invité : pas de CSRF par le cookie.
func (l *Local) User(r *http.Request) *User {
	if _, a, ok := l.session(r); ok {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r, true) {
			return nil
		}
		return &User{ID: a.ID, Name: a.Name}
	}
	return nil
}

// session renvoie l'empreinte et le compte de la session du cookie.
func (l *Local) session(r *http.Request) (string, Account, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return "", Account{}, false
	}
	h := hashToken(c.Value)
	now := l.now()
	if v, ok := l.cache.Load(h); ok && now.Before(v.(cached).until) {
		return h, v.(cached).account, true
	}
	a, err := l.store.SessionAccount(r.Context(), h, now)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			l.log.Error("session", "err", err)
		}
		return "", Account{}, false
	}
	l.cache.Store(h, cached{account: a, until: now.Add(cacheTTL)})
	return h, a, true
}

// forget efface une session du cache (déconnexion, changement de nom ou de mot de passe).
func (l *Local) forget(hash string) { l.cache.Delete(hash) }

func (l *Local) forgetAccount(id string) {
	l.cache.Range(func(k, v any) bool {
		if v.(cached).account.ID == id {
			l.cache.Delete(k)
		}
		return true
	})
}

func (l *Local) openSession(w http.ResponseWriter, r *http.Request, a Account) error {
	token := randomCode()
	now := l.now()
	if err := l.store.CreateSession(r.Context(), hashToken(token), a.ID, now.Add(sessionTTL), now); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode})
	if err := l.store.Purge(context.WithoutCancel(r.Context()), now); err != nil {
		l.log.Warn("ménage des sessions", "err", err)
	}
	return nil
}

func (l *Local) closeSession(w http.ResponseWriter, r *http.Request) {
	if h, _, ok := l.session(r); ok {
		if err := l.store.DeleteSession(r.Context(), h); err != nil {
			l.log.Error("déconnexion", "err", err)
		}
		l.forget(h)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode})
}

var errSlowDown = errors.New("trop de tentatives : réessaie dans une minute")

// allow limite les tentatives par nom (5 par minute) et par adresse (30 par minute).
func (l *Local) allow(r *http.Request, username string) error {
	l.limitMu.Lock()
	defer l.limitMu.Unlock()
	if len(l.limits) > 10000 {
		l.limits = map[string]*rate.Limiter{}
	}
	get := func(k string, n int) *rate.Limiter {
		if lim, ok := l.limits[k]; ok {
			return lim
		}
		lim := rate.NewLimiter(rate.Every(time.Minute/time.Duration(n)), n)
		l.limits[k] = lim
		return lim
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !get("ip:"+host, 30).Allow() {
		return errSlowDown
	}
	if username != "" && !get("u:"+username, 5).Allow() {
		return errSlowDown
	}
	return nil
}

// ---- règles

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

func normUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func checkUsername(u string) error {
	if !usernameRe.MatchString(u) {
		return errors.New("nom d'utilisateur : 3 à 32 caractères, lettres minuscules, chiffres, point, tiret ou soulignement")
	}
	return nil
}

func cleanName(name, fallback string) (string, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		name = fallback
	}
	if utf8.RuneCountInString(name) > 40 {
		return "", errors.New("nom affiché : 40 caractères au plus")
	}
	return name, nil
}

func checkPasswordRules(password, username string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < 10:
		return errors.New("mot de passe : 10 caractères au moins")
	case n > 200:
		return errors.New("mot de passe : 200 caractères au plus")
	case strings.EqualFold(password, username):
		return errors.New("le mot de passe ne peut pas être le nom d'utilisateur")
	}
	return nil
}

// ---- outils

func randomCode() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// sameOrigin : la requête vient-elle du site lui-même ? On regarde Origin, puis
// Referer. Sans l'un ni l'autre : strict refuse (formulaires des pages de
// comptes), sinon accepte (clients qui n'envoient pas Origin, comme les tests).
func sameOrigin(r *http.Request, lenient bool) bool {
	src := r.Header.Get("Origin")
	if src == "" || src == "null" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return lenient
	}
	u, err := url.Parse(src)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
}

// safeNext garde une adresse de retour sur le site lui-même.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

func absURL(r *http.Request, path string) string {
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host + path
}
