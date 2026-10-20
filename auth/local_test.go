package auth

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

type site struct {
	t     *testing.T
	local *Local
	srv   *httptest.Server
}

func newSite(t *testing.T, signup string) *site {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	store, err := NewSQLStore(context.Background(), db, SQLite)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), Config{Mode: ModeLocal, GuestPlay: true, Signup: signup, LocalStore: store,
		Theme: Theme{Title: "Orapa"}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	l := a.(*Local)
	mux := http.NewServeMux()
	l.Mount(mux)
	// Une route du jeu : renvoie le compte de la requête.
	mux.HandleFunc("/api/qui", func(w http.ResponseWriter, r *http.Request) {
		if u := l.User(r); u != nil {
			_, _ = io.WriteString(w, u.Name)
		}
	})
	s := &site{t: t, local: l, srv: httptest.NewServer(mux)}
	t.Cleanup(s.srv.Close)
	return s
}

// browser : un navigateur, avec ses cookies, qui ne suit pas les redirections.
type browser struct {
	s *site
	c *http.Client
}

func (s *site) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{s: s, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) get(path string) (int, string) {
	b.s.t.Helper()
	res, err := b.c.Get(b.s.srv.URL + path)
	if err != nil {
		b.s.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode == http.StatusSeeOther {
		return res.StatusCode, res.Header.Get("Location")
	}
	return res.StatusCode, string(body)
}

func (b *browser) postFrom(origin, path string, form url.Values) (int, string) {
	b.s.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.s.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	res, err := b.c.Do(req)
	if err != nil {
		b.s.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode == http.StatusSeeOther {
		return res.StatusCode, res.Header.Get("Location")
	}
	return res.StatusCode, string(body)
}

func (b *browser) post(path string, form url.Values) (int, string) {
	return b.postFrom(b.s.srv.URL, path, form)
}

func (b *browser) who() string {
	_, body := b.get("/api/qui")
	return body
}

func signupForm(user, pw, invite string) url.Values {
	return url.Values{"username": {user}, "name": {""}, "password": {pw}, "password2": {pw}, "invitation": {invite}, "next": {"/partie"}}
}

var linkRe = regexp.MustCompile(`<p class="copy">([^<]+)</p>`)

func link(t *testing.T, body string) string {
	t.Helper()
	m := linkRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("pas de lien dans la page")
	}
	u, err := url.Parse(strings.ReplaceAll(m[1], "&amp;", "&"))
	if err != nil {
		t.Fatal(err)
	}
	return u.RequestURI()
}

func TestLocalFlow(t *testing.T) {
	s := newSite(t, SignupInvite)
	alice := s.browser()

	// Instance neuve : la connexion mène à la création du premier compte.
	if st, loc := alice.get("/compte/connexion?next=/partie"); st != http.StatusSeeOther || !strings.HasPrefix(loc, "/compte/inscription") {
		t.Fatalf("instance neuve : %d %s", st, loc)
	}
	if _, body := alice.get("/compte/inscription"); !strings.Contains(body, "Créer le premier compte") {
		t.Fatal("pas de page de premier compte")
	}
	// Un formulaire venu d'un autre site est refusé.
	if st, _ := alice.postFrom("https://ailleurs.example", "/compte/inscription", signupForm("alice", "un bon mot de passe", "")); st != http.StatusForbidden {
		t.Fatalf("CSRF : %d", st)
	}
	if st, _ := alice.postFrom("", "/compte/inscription", signupForm("alice", "un bon mot de passe", "")); st != http.StatusForbidden {
		t.Fatalf("sans Origin : %d", st)
	}
	if st, _ := alice.post("/compte/inscription", signupForm("alice", "court", "")); st != http.StatusBadRequest {
		t.Fatalf("mot de passe court : %d", st)
	}
	if st, loc := alice.post("/compte/inscription", signupForm("Alice", "un bon mot de passe", "")); st != http.StatusSeeOther || loc != "/partie" {
		t.Fatalf("premier compte : %d %s", st, loc)
	}
	if alice.who() != "alice" {
		t.Fatalf("session : %q", alice.who())
	}
	if _, body := alice.get("/compte/"); !strings.Contains(body, "administrateur") {
		t.Fatal("le premier compte n'est pas administrateur")
	}

	// Sans invitation, plus d'inscription.
	bob := s.browser()
	if st, _ := bob.post("/compte/inscription", signupForm("bob", "un autre mot de passe", "")); st != http.StatusForbidden {
		t.Fatalf("sans invitation : %d", st)
	}
	if st, _ := bob.post("/compte/inscription", signupForm("bob", "un autre mot de passe", "faux")); st != http.StatusForbidden {
		t.Fatalf("fausse invitation : %d", st)
	}
	// Alice invite Bob.
	_, body := alice.post("/compte/admin/invitation", nil)
	invite := link(t, body)
	code := strings.TrimPrefix(invite, "/compte/inscription?invitation=")
	if st, _ := bob.post("/compte/inscription", signupForm("alice", "un autre mot de passe", code)); st != http.StatusConflict {
		t.Fatalf("nom pris : %d", st)
	}
	if st, _ := bob.post("/compte/inscription", signupForm("bob", "un autre mot de passe", code)); st != http.StatusSeeOther || bob.who() != "bob" {
		t.Fatalf("inscription invitée : %d %q", st, bob.who())
	}
	carol := s.browser()
	if st, _ := carol.post("/compte/inscription", signupForm("carol", "encore un mot de passe", code)); st != http.StatusForbidden {
		t.Fatalf("invitation réutilisée : %d", st)
	}
	// Bob n'est pas administrateur.
	if st, _ := bob.get("/compte/admin"); st != http.StatusForbidden {
		t.Fatalf("admin pour bob : %d", st)
	}

	// Connexion sur un autre appareil, puis changement de mot de passe : l'autre appareil est déconnecté.
	bob2 := s.browser()
	if st, _ := bob2.post("/compte/connexion", url.Values{"username": {"BOB"}, "password": {"pas le bon"}}); st != http.StatusUnauthorized {
		t.Fatalf("mauvais mot de passe : %d", st)
	}
	if st, _ := bob2.post("/compte/connexion", url.Values{"username": {"bob"}, "password": {"un autre mot de passe"}, "next": {"//ailleurs.example"}}); st != http.StatusSeeOther || bob2.who() != "bob" {
		t.Fatalf("connexion : %d", st)
	}
	if st, _ := bob.post("/compte/mot-de-passe", url.Values{"current": {"faux"}, "password": {"nouveau mot de passe"}, "password2": {"nouveau mot de passe"}}); st != http.StatusUnauthorized {
		t.Fatalf("mot de passe actuel faux : %d", st)
	}
	if st, _ := bob.post("/compte/mot-de-passe", url.Values{"current": {"un autre mot de passe"}, "password": {"nouveau mot de passe"}, "password2": {"nouveau mot de passe"}}); st != http.StatusSeeOther {
		t.Fatalf("changement : %d", st)
	}
	if bob.who() != "bob" || bob2.who() != "" {
		t.Fatalf("après changement : ici %q, ailleurs %q", bob.who(), bob2.who())
	}
	// Nom affiché.
	if st, _ := bob.post("/compte/nom", url.Values{"name": {"  Bob   le Malin "}}); st != http.StatusSeeOther || bob.who() != "Bob le Malin" {
		t.Fatalf("nom : %d %q", st, bob.who())
	}

	// Lien de nouveau mot de passe, créé par Alice pour Bob.
	accounts, _ := s.local.store.Accounts(context.Background())
	_, body = alice.post("/compte/admin/reinitialisation", url.Values{"account": {accounts[1].ID}})
	reset := link(t, body)
	resetCode := strings.TrimPrefix(reset, "/compte/reinitialisation?code=")
	if st, _ := carol.post("/compte/reinitialisation", url.Values{"code": {resetCode}, "password": {"court"}, "password2": {"court"}}); st != http.StatusBadRequest {
		t.Fatalf("réinitialisation trop courte : %d", st)
	}
	if st, _ := carol.post("/compte/reinitialisation", url.Values{"code": {resetCode}, "password": {"encore un nouveau"}, "password2": {"encore un nouveau"}}); st != http.StatusOK {
		t.Fatalf("réinitialisation : %d", st)
	}
	if bob.who() != "" {
		t.Fatal("session de bob encore ouverte après réinitialisation")
	}
	if st, _ := carol.post("/compte/reinitialisation", url.Values{"code": {resetCode}, "password": {"encore un autre"}, "password2": {"encore un autre"}}); st != http.StatusGone {
		t.Fatalf("lien réutilisé : %d", st)
	}
	if st, _ := bob.post("/compte/connexion", url.Values{"username": {"bob"}, "password": {"encore un nouveau"}}); st != http.StatusSeeOther {
		t.Fatalf("connexion après réinitialisation : %d", st)
	}

	// Une requête du jeu venue d'un autre site ne compte pas comme connectée.
	req, _ := http.NewRequest(http.MethodPost, s.srv.URL+"/api/qui", nil)
	req.Header.Set("Origin", "https://ailleurs.example")
	res, _ := alice.c.Do(req)
	got, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if len(got) != 0 {
		t.Fatalf("POST d'un autre site connecté comme %q", got)
	}

	// Déconnexion.
	if st, loc := alice.post("/compte/deconnexion", url.Values{"next": {"/partie"}}); st != http.StatusSeeOther || loc != "/partie" || alice.who() != "" {
		t.Fatalf("déconnexion : %d %s %q", st, loc, alice.who())
	}
}

func TestLocalLimits(t *testing.T) {
	s := newSite(t, SignupOpen)
	a := s.browser()
	a.post("/compte/inscription", signupForm("alice", "un bon mot de passe", ""))
	// Inscription libre : un deuxième compte sans invitation.
	if st, _ := s.browser().post("/compte/inscription", signupForm("bob", "un autre mot de passe", "")); st != http.StatusSeeOther {
		t.Fatalf("inscription libre : %d", st)
	}
	m := s.browser()
	var st int
	for range 6 {
		st, _ = m.post("/compte/connexion", url.Values{"username": {"alice"}, "password": {"essai"}})
	}
	if st != http.StatusTooManyRequests {
		t.Fatalf("6e essai : %d", st)
	}
}

func TestLocalClosed(t *testing.T) {
	s := newSite(t, SignupClosed)
	s.browser().post("/compte/inscription", signupForm("alice", "un bon mot de passe", ""))
	if st, _ := s.browser().post("/compte/inscription", signupForm("bob", "un autre mot de passe", "")); st != http.StatusForbidden {
		t.Fatalf("inscription fermée : %d", st)
	}
	if _, err := New(context.Background(), Config{Mode: ModeLocal, GuestPlay: true}, nil); err == nil {
		t.Fatal("mode local sans store accepté")
	}
	if _, err := New(context.Background(), Config{Mode: ModeLocal, GuestPlay: true, Signup: "parfois", LocalStore: s.local.store}, nil); err == nil {
		t.Fatal("SIGNUP inconnu accepté")
	}
}

func TestPassword(t *testing.T) {
	h, err := hashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := checkPassword("correct horse", h); !ok {
		t.Fatal("bon mot de passe refusé")
	}
	if ok, _ := checkPassword("Correct horse", h); ok {
		t.Fatal("mauvais mot de passe accepté")
	}
	if _, err := checkPassword("x", "$bcrypt$..."); err == nil {
		t.Fatal("empreinte illisible acceptée")
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/partie/x": "/partie/x", "//evil.example": "/", "https://evil.example": "/", "/\\evil": "/", "": "/"} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
}

func TestPostgresPlaceholders(t *testing.T) {
	s := &SQLStore{dialect: Postgres}
	if got := s.q(`UPDATE t SET a = ? WHERE b = ? AND c = ?`); got != `UPDATE t SET a = $1 WHERE b = $2 AND c = $3` {
		t.Fatal(got)
	}
}
