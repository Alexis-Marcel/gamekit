package auth

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"net/http"
)

// Pages du mode local, rendues côté serveur, sans JavaScript, aux couleurs du jeu.

//go:embed pages/*.html
var pageFiles embed.FS

func parsePages() (*template.Template, error) {
	return template.ParseFS(pageFiles, "pages/*.html")
}

// Theme : l'allure des pages de comptes, donnée par le jeu pour qu'elles lui ressemblent.
type Theme struct {
	Title      string // nom du jeu
	Background string
	Surface    string
	Text       string
	Muted      string
	Line       string
	Accent     string
	OnAccent   string // texte sur l'accent
	Danger     string
	Font       string       // pile de polices CSS
	FontURL    template.URL // feuille de style des polices (facultative)
}

func (t *Theme) defaults() {
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&t.Title, "Jeu")
	def(&t.Background, "#14161c")
	def(&t.Surface, "#1c1f27")
	def(&t.Text, "#ecedf0")
	def(&t.Muted, "#9ba0ad")
	def(&t.Line, "#2c303b")
	def(&t.Accent, "#e8b86b")
	def(&t.OnAccent, "#14161c")
	def(&t.Danger, "#ff6b6b")
	def(&t.Font, "system-ui, -apple-system, \"Segoe UI\", sans-serif")
}

type page struct {
	Theme      Theme
	Title      string
	Flash      string
	Error      string
	Next       string
	Wide       bool
	Signup     string
	CanSignup  bool
	First      bool
	Username   string
	Name       string
	Invitation string
	Code       string
	Account    Account
	Accounts   []Account
	Link       string
	LinkTitle  string
	LinkHelp   string
	Text       string
	Action     string
	ActionURL  string
}

func (l *Local) render(w http.ResponseWriter, status int, name string, p page) {
	p.Theme = l.theme
	p.Signup = l.signup
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.WriteHeader(status)
	if err := l.pages.ExecuteTemplate(w, name, p); err != nil {
		l.log.Error("page de comptes", "page", name, "err", err)
	}
}

func (l *Local) message(w http.ResponseWriter, status int, title, text, action, actionURL string) {
	l.render(w, status, "message", page{Title: title, Text: text, Action: action, ActionURL: actionURL})
}

// Mount sert les pages de comptes sous /compte/.
func (l *Local) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET "+base+"/connexion", l.loginPage)
	mux.HandleFunc("POST "+base+"/connexion", l.post(l.login))
	mux.HandleFunc("GET "+base+"/inscription", l.signupPage)
	mux.HandleFunc("POST "+base+"/inscription", l.post(l.signupPost))
	mux.HandleFunc("POST "+base+"/deconnexion", l.post(l.logout))
	mux.HandleFunc("GET "+base+"/{$}", l.accountPage)
	mux.HandleFunc("POST "+base+"/nom", l.post(l.rename))
	mux.HandleFunc("POST "+base+"/mot-de-passe", l.post(l.changePassword))
	mux.HandleFunc("GET "+base+"/admin", l.admin(l.adminPage))
	mux.HandleFunc("POST "+base+"/admin/invitation", l.post(l.admin(l.invite)))
	mux.HandleFunc("POST "+base+"/admin/reinitialisation", l.post(l.admin(l.resetLink)))
	mux.HandleFunc("GET "+base+"/reinitialisation", l.resetPage)
	mux.HandleFunc("POST "+base+"/reinitialisation", l.post(l.reset))
}

// post refuse un formulaire venu d'un autre site (CSRF) et lit ses champs.
func (l *Local) post(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r, false) {
			l.message(w, http.StatusForbidden, "Requête refusée", "Ce formulaire ne vient pas de ce site.", "", "")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			l.message(w, http.StatusBadRequest, "Requête illisible", "Le formulaire n'a pas pu être lu.", "", "")
			return
		}
		h(w, r)
	}
}

// admin réserve une page aux administrateurs.
func (l *Local) admin(h func(http.ResponseWriter, *http.Request, Account)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, a, ok := l.session(r)
		if !ok {
			http.Redirect(w, r, base+"/connexion?next="+base+"/admin", http.StatusSeeOther)
			return
		}
		if !a.Admin {
			l.message(w, http.StatusForbidden, "Réservé aux administrateurs", "Ton compte n'a pas accès à cette page.", "Mon compte", base+"/")
			return
		}
		h(w, r, a)
	}
}

func (l *Local) fail(w http.ResponseWriter, err error) {
	l.log.Error("comptes", "err", err)
	l.message(w, http.StatusInternalServerError, "Erreur", "Quelque chose n'a pas marché de notre côté. Réessaie dans un instant.", "", "")
}

// canSignup : qui peut s'inscrire maintenant (first : aucun compte encore).
func (l *Local) canSignup(ctx context.Context, invitation string) (can, first bool, err error) {
	n, err := l.store.CountAccounts(ctx)
	if err != nil {
		return false, false, err
	}
	switch {
	case n == 0:
		return true, true, nil
	case l.signup == SignupOpen:
		return true, false, nil
	case l.signup == SignupInvite:
		return invitation != "", false, nil
	}
	return false, false, nil
}

// ---- connexion

func (l *Local) loginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, _, ok := l.session(r); ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	can, first, err := l.canSignup(r.Context(), "")
	if err != nil {
		l.fail(w, err)
		return
	}
	if first {
		http.Redirect(w, r, base+"/inscription?next="+next, http.StatusSeeOther)
		return
	}
	l.render(w, http.StatusOK, "connexion", page{Title: "Se connecter", Next: next, CanSignup: can})
}

func (l *Local) login(w http.ResponseWriter, r *http.Request) {
	username := normUsername(r.PostFormValue("username"))
	next := safeNext(r.PostFormValue("next"))
	can, _, _ := l.canSignup(r.Context(), "")
	again := func(status int, msg string) {
		l.render(w, status, "connexion", page{Title: "Se connecter", Next: next, CanSignup: can, Username: username, Error: msg})
	}
	if err := l.allow(r, username); err != nil {
		again(http.StatusTooManyRequests, err.Error())
		return
	}
	a, hash, err := l.store.AccountByUsername(r.Context(), username)
	if err != nil && !errors.Is(err, ErrNotFound) {
		l.fail(w, err)
		return
	}
	if errors.Is(err, ErrNotFound) {
		hash = dummyHash // même temps de réponse : ne dit pas si le nom existe
	}
	ok, cerr := checkPassword(r.PostFormValue("password"), hash)
	if cerr != nil || !ok || err != nil {
		again(http.StatusUnauthorized, "Nom d'utilisateur ou mot de passe incorrect.")
		return
	}
	if err := l.openSession(w, r, a); err != nil {
		l.fail(w, err)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (l *Local) logout(w http.ResponseWriter, r *http.Request) {
	l.closeSession(w, r)
	http.Redirect(w, r, safeNext(r.PostFormValue("next")), http.StatusSeeOther)
}

// ---- inscription

func (l *Local) signupPage(w http.ResponseWriter, r *http.Request) {
	invitation := r.URL.Query().Get("invitation")
	can, first, err := l.canSignup(r.Context(), invitation)
	if err != nil {
		l.fail(w, err)
		return
	}
	l.render(w, http.StatusOK, "inscription", page{Title: "Créer un compte", Next: safeNext(r.URL.Query().Get("next")),
		CanSignup: can, First: first, Invitation: invitation})
}

func (l *Local) signupPost(w http.ResponseWriter, r *http.Request) {
	username := normUsername(r.PostFormValue("username"))
	invitation := r.PostFormValue("invitation")
	next := safeNext(r.PostFormValue("next"))
	can, first, err := l.canSignup(r.Context(), invitation)
	if err != nil {
		l.fail(w, err)
		return
	}
	p := page{Title: "Créer un compte", Next: next, CanSignup: can, First: first, Invitation: invitation,
		Username: username, Name: r.PostFormValue("name")}
	again := func(status int, msg string) {
		p.Error = msg
		l.render(w, status, "inscription", p)
	}
	if !can {
		again(http.StatusForbidden, "Inscription impossible sans invitation.")
		return
	}
	if err := l.allow(r, ""); err != nil {
		again(http.StatusTooManyRequests, err.Error())
		return
	}
	name, err := cleanName(r.PostFormValue("name"), username)
	if err == nil {
		err = checkUsername(username)
	}
	if err == nil {
		err = checkPasswordRules(r.PostFormValue("password"), username)
	}
	if err == nil && r.PostFormValue("password") != r.PostFormValue("password2") {
		err = errors.New("les deux mots de passe ne sont pas les mêmes")
	}
	if err != nil {
		again(http.StatusBadRequest, capitalize(err.Error())+".")
		return
	}
	hash, err := hashPassword(r.PostFormValue("password"))
	if err != nil {
		l.fail(w, err)
		return
	}
	inviteHash := ""
	if !first && l.signup == SignupInvite {
		inviteHash = hashToken(invitation)
	}
	a, err := l.store.Signup(r.Context(), Account{ID: newUUID(), Username: username, Name: name}, hash, inviteHash, l.now())
	switch {
	case errors.Is(err, ErrTaken):
		again(http.StatusConflict, "Ce nom d'utilisateur est déjà pris.")
		return
	case errors.Is(err, ErrNotFound):
		p.CanSignup, p.Invitation = false, ""
		again(http.StatusForbidden, "Cette invitation n'est plus valable : demande un nouveau lien.")
		return
	case err != nil:
		l.fail(w, err)
		return
	}
	if err := l.openSession(w, r, a); err != nil {
		l.fail(w, err)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ---- compte

func (l *Local) accountPage(w http.ResponseWriter, r *http.Request) {
	_, a, ok := l.session(r)
	if !ok {
		http.Redirect(w, r, base+"/connexion?next="+base+"/", http.StatusSeeOther)
		return
	}
	l.render(w, http.StatusOK, "compte", page{Title: "Mon compte", Account: a, Flash: flash(r.URL.Query().Get("ok"))})
}

func flash(code string) string {
	switch code {
	case "nom":
		return "Nom enregistré."
	case "mot-de-passe":
		return "Mot de passe changé. Tes autres appareils sont déconnectés."
	}
	return ""
}

func (l *Local) rename(w http.ResponseWriter, r *http.Request) {
	_, a, ok := l.session(r)
	if !ok {
		http.Redirect(w, r, base+"/connexion?next="+base+"/", http.StatusSeeOther)
		return
	}
	name, err := cleanName(r.PostFormValue("name"), a.Username)
	if err != nil {
		l.render(w, http.StatusBadRequest, "compte", page{Title: "Mon compte", Account: a, Error: capitalize(err.Error()) + "."})
		return
	}
	if err := l.store.SetName(r.Context(), a.ID, name); err != nil {
		l.fail(w, err)
		return
	}
	l.forgetAccount(a.ID)
	http.Redirect(w, r, base+"/?ok=nom", http.StatusSeeOther)
}

func (l *Local) changePassword(w http.ResponseWriter, r *http.Request) {
	h, a, ok := l.session(r)
	if !ok {
		http.Redirect(w, r, base+"/connexion?next="+base+"/", http.StatusSeeOther)
		return
	}
	again := func(status int, msg string) {
		l.render(w, status, "compte", page{Title: "Mon compte", Account: a, Error: msg})
	}
	if err := l.allow(r, a.Username); err != nil {
		again(http.StatusTooManyRequests, err.Error())
		return
	}
	_, hash, err := l.store.AccountByUsername(r.Context(), a.Username)
	if err != nil {
		l.fail(w, err)
		return
	}
	if ok, _ := checkPassword(r.PostFormValue("current"), hash); !ok {
		again(http.StatusUnauthorized, "Le mot de passe actuel n'est pas le bon.")
		return
	}
	pw := r.PostFormValue("password")
	if err := checkPasswordRules(pw, a.Username); err != nil {
		again(http.StatusBadRequest, capitalize(err.Error())+".")
		return
	}
	if pw != r.PostFormValue("password2") {
		again(http.StatusBadRequest, "Les deux mots de passe ne sont pas les mêmes.")
		return
	}
	if err := l.setPassword(r.Context(), a.ID, pw, h); err != nil {
		l.fail(w, err)
		return
	}
	http.Redirect(w, r, base+"/?ok=mot-de-passe", http.StatusSeeOther)
}

// setPassword change le mot de passe et ferme les autres sessions (sauf keep).
func (l *Local) setPassword(ctx context.Context, id, password, keep string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	if err := l.store.SetPassword(ctx, id, hash); err != nil {
		return err
	}
	if err := l.store.DeleteSessions(ctx, id, keep); err != nil {
		return err
	}
	l.forgetAccount(id)
	return nil
}

// ---- administration

func (l *Local) adminPage(w http.ResponseWriter, r *http.Request, _ Account) {
	l.renderAdmin(w, r, page{})
}

func (l *Local) renderAdmin(w http.ResponseWriter, r *http.Request, p page) {
	accounts, err := l.store.Accounts(r.Context())
	if err != nil {
		l.fail(w, err)
		return
	}
	p.Title, p.Wide, p.Accounts = "Administration", true, accounts
	l.render(w, http.StatusOK, "admin", p)
}

func (l *Local) invite(w http.ResponseWriter, r *http.Request, a Account) {
	code := randomCode()
	now := l.now()
	if err := l.store.CreateTicket(r.Context(), Ticket{Hash: hashToken(code), Kind: TicketInvite, CreatedBy: a.ID, Expires: now.Add(inviteTTL)}, now); err != nil {
		l.fail(w, err)
		return
	}
	l.renderAdmin(w, r, page{Link: absURL(r, base+"/inscription?invitation="+code), LinkTitle: "Lien d'invitation",
		LinkHelp: "Envoie ce lien à la personne : il lui permet de créer un compte, une seule fois, pendant 7 jours. Il ne sera plus affiché."})
}

func (l *Local) resetLink(w http.ResponseWriter, r *http.Request, a Account) {
	target := r.PostFormValue("account")
	accounts, err := l.store.Accounts(r.Context())
	if err != nil {
		l.fail(w, err)
		return
	}
	var who *Account
	for i := range accounts {
		if accounts[i].ID == target {
			who = &accounts[i]
		}
	}
	if who == nil {
		l.renderAdmin(w, r, page{Error: "Ce compte n'existe plus."})
		return
	}
	code := randomCode()
	now := l.now()
	if err := l.store.CreateTicket(r.Context(), Ticket{Hash: hashToken(code), Kind: TicketReset, AccountID: who.ID, CreatedBy: a.ID, Expires: now.Add(resetTTL)}, now); err != nil {
		l.fail(w, err)
		return
	}
	l.renderAdmin(w, r, page{Link: absURL(r, base+"/reinitialisation?code="+code), LinkTitle: "Nouveau mot de passe pour " + who.Name,
		LinkHelp: "Envoie ce lien à " + who.Name + " : il permet de choisir un nouveau mot de passe, une seule fois, pendant 24 heures. Il ne sera plus affiché."})
}

// ---- réinitialisation

func (l *Local) resetPage(w http.ResponseWriter, r *http.Request) {
	l.render(w, http.StatusOK, "reinitialisation", page{Title: "Nouveau mot de passe", Code: r.URL.Query().Get("code")})
}

func (l *Local) reset(w http.ResponseWriter, r *http.Request) {
	code, pw := r.PostFormValue("code"), r.PostFormValue("password")
	again := func(status int, msg string) {
		l.render(w, status, "reinitialisation", page{Title: "Nouveau mot de passe", Code: code, Error: msg})
	}
	if err := l.allow(r, ""); err != nil {
		again(http.StatusTooManyRequests, err.Error())
		return
	}
	// Le mot de passe est vérifié avant de consommer le lien : une faute de frappe ne le gâche pas.
	if err := checkPasswordRules(pw, ""); err != nil {
		again(http.StatusBadRequest, capitalize(err.Error())+".")
		return
	}
	if pw != r.PostFormValue("password2") {
		again(http.StatusBadRequest, "Les deux mots de passe ne sont pas les mêmes.")
		return
	}
	t, err := l.store.UseTicket(r.Context(), hashToken(code), TicketReset, l.now())
	if errors.Is(err, ErrNotFound) {
		l.message(w, http.StatusGone, "Lien expiré", "Ce lien a déjà servi ou n'est plus valable. Demande-en un nouveau à un administrateur.", "", "")
		return
	}
	if err != nil {
		l.fail(w, err)
		return
	}
	if err := l.setPassword(r.Context(), t.AccountID, pw, ""); err != nil {
		l.fail(w, err)
		return
	}
	l.message(w, http.StatusOK, "Mot de passe changé", "Tu peux te connecter avec ton nouveau mot de passe.", "Se connecter", base+"/connexion")
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] -= 'a' - 'A'
	}
	return string(r)
}
