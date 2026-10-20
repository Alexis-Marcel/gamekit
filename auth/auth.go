// Package auth identifie le compte derrière une requête, selon une méthode
// choisie par celui qui héberge le jeu (AUTH_MODE), à la manière des apps *arr :
//
//   - none : pas de comptes, tout le monde joue en invité ;
//   - oidc : jeton d'accès d'un fournisseur OIDC (Authentik, Keycloak,
//     Authelia, Google…), vérifié par sa JWKS ;
//   - proxy : en-tête posé par un reverse proxy qui authentifie déjà (forward
//     auth d'Authelia ou d'Authentik, Tailscale Serve), cru seulement s'il
//     vient d'une adresse de confiance ;
//   - local : comptes intégrés au jeu (nom d'utilisateur et mot de passe),
//     avec leurs pages sous /compte/ (voir Local).
//
// Le compte est toujours facultatif pour le jeu lui-même : une place se tient
// par son jeton de place. Avec GUEST_PLAY=false, le jeu exige un compte pour
// créer ou rejoindre une partie (voir Info.GuestPlay).
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
)

// User est un compte : ID est stable (le sub OIDC), Name est le nom affiché.
// Email est facultatif : donné par le fournisseur OIDC ou par le proxy.
type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"-"` // jamais renvoyé au front par défaut
}

// Authenticator renvoie le compte d'une requête, nil pour un invité (pas de
// jeton, ou jeton refusé : on ne bloque jamais une requête pour ça).
type Authenticator interface {
	User(r *http.Request) *User
	// Info : ce que le front doit savoir pour afficher la bonne connexion.
	Info() Info
}

// Info est servi tel quel au front (dans /api/config).
type Info struct {
	Mode        string     `json:"mode"`                  // none, oidc, proxy, local
	AccountName string     `json:"accountName,omitempty"` // « Se connecter avec … » ; vide : « Se connecter »
	GuestPlay   bool       `json:"guestPlay"`             // jouer sans compte est permis
	OIDC        *OIDCInfo  `json:"oidc,omitempty"`
	Proxy       *ProxyInfo `json:"proxy,omitempty"`
	Local       *LocalInfo `json:"local,omitempty"`
}

// ProxyInfo : où envoyer pour se connecter ou se déconnecter (chez le proxy).
type ProxyInfo struct {
	LoginURL  string `json:"loginUrl,omitempty"`
	LogoutURL string `json:"logoutUrl,omitempty"`
}

type OIDCInfo struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"clientId"`
	// Metadata : la découverte déjà faite par le serveur au démarrage. Le front
	// la passe à son client OIDC et s'épargne un aller-retour chez le
	// fournisseur à chaque chargement.
	Metadata *Metadata `json:"metadata,omitempty"`
}

// Metadata reprend les champs de /.well-known/openid-configuration dont un
// client navigateur a besoin, sous leurs noms standard.
type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri"`
}

const (
	ModeNone  = "none"
	ModeOIDC  = "oidc"
	ModeProxy = "proxy"
	ModeLocal = "local"
)

// Config est la configuration d'authentification d'un jeu.
type Config struct {
	Mode         string // vide : oidc si OIDCIssuer est donné, sinon none
	AccountName  string
	GuestPlay    bool
	OIDCIssuer   string
	OIDCClientID string
	OIDCAudience string // vide : OIDCClientID

	ProxyUserHeader  string         // vide : Remote-User
	ProxyNameHeader  string         // vide : Remote-Name
	ProxyEmailHeader string         // vide : Remote-Email
	TrustedProxies   []netip.Prefix // obligatoire en mode proxy
	ProxyLoginURL    string
	ProxyLogoutURL   string

	Signup     string     // mode local : open, invite (défaut), closed
	LocalStore LocalStore // mode local : fournie par le jeu, pas par l'environnement
	Theme      Theme      // mode local : couleurs des pages de comptes, fournies par le jeu
}

// FromEnv lit AUTH_MODE, ACCOUNT_NAME, GUEST_PLAY (vrai par défaut), OIDC_ISSUER,
// OIDC_CLIENT_ID (défaut : clientID, le nom du jeu), OIDC_AUDIENCE, et pour le
// mode proxy PROXY_USER_HEADER, PROXY_NAME_HEADER, PROXY_EMAIL_HEADER, TRUSTED_PROXIES (adresses ou
// plages séparées par des virgules), PROXY_LOGIN_URL et PROXY_LOGOUT_URL, et pour
// le mode local SIGNUP.
func FromEnv(getenv func(string) string, clientID string) (Config, error) {
	c := Config{
		Mode:         strings.ToLower(strings.TrimSpace(getenv("AUTH_MODE"))),
		AccountName:  strings.TrimSpace(getenv("ACCOUNT_NAME")),
		GuestPlay:    true,
		OIDCIssuer:   getenv("OIDC_ISSUER"),
		OIDCClientID: getenv("OIDC_CLIENT_ID"),
		OIDCAudience: getenv("OIDC_AUDIENCE"),

		ProxyUserHeader:  strings.TrimSpace(getenv("PROXY_USER_HEADER")),
		ProxyNameHeader:  strings.TrimSpace(getenv("PROXY_NAME_HEADER")),
		ProxyEmailHeader: strings.TrimSpace(getenv("PROXY_EMAIL_HEADER")),
		ProxyLoginURL:    strings.TrimSpace(getenv("PROXY_LOGIN_URL")),
		ProxyLogoutURL:   strings.TrimSpace(getenv("PROXY_LOGOUT_URL")),
		Signup:           strings.ToLower(strings.TrimSpace(getenv("SIGNUP"))),
	}
	for _, f := range strings.Split(getenv("TRUSTED_PROXIES"), ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := parsePrefix(f)
		if err != nil {
			return c, fmt.Errorf("TRUSTED_PROXIES : %q n'est ni une adresse ni une plage", f)
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}
	if c.OIDCClientID == "" {
		c.OIDCClientID = clientID
	}
	switch strings.ToLower(strings.TrimSpace(getenv("GUEST_PLAY"))) {
	case "", "true", "1", "yes", "oui":
	case "false", "0", "no", "non":
		c.GuestPlay = false
	default:
		return c, fmt.Errorf("GUEST_PLAY : %q, attendu true ou false", getenv("GUEST_PLAY"))
	}
	return c, nil
}

// New construit l'authentification décrite par la config. En mode oidc, elle
// contacte le fournisseur (découverte, JWKS) : à appeler au démarrage.
func New(ctx context.Context, c Config, log *slog.Logger) (Authenticator, error) {
	if log == nil {
		log = slog.Default()
	}
	mode := c.Mode
	if mode == "" {
		mode = ModeNone
		if c.OIDCIssuer != "" {
			mode = ModeOIDC
		}
	}
	info := Info{Mode: mode, AccountName: c.AccountName, GuestPlay: c.GuestPlay}
	switch mode {
	case ModeNone:
		if !c.GuestPlay {
			return nil, fmt.Errorf("AUTH_MODE=none et GUEST_PLAY=false : personne ne pourrait jouer")
		}
		return None{}, nil
	case ModeOIDC:
		if c.OIDCIssuer == "" || c.OIDCClientID == "" {
			return nil, fmt.Errorf("AUTH_MODE=oidc : OIDC_ISSUER et OIDC_CLIENT_ID sont nécessaires")
		}
		aud := c.OIDCAudience
		if aud == "" {
			aud = c.OIDCClientID
		}
		v, err := NewVerifier(ctx, c.OIDCIssuer, aud)
		if err != nil {
			return nil, err
		}
		info.OIDC = &OIDCInfo{Issuer: c.OIDCIssuer, ClientID: c.OIDCClientID, Metadata: v.metadata}
		return &OIDC{verifier: v, info: info, log: log}, nil
	case ModeProxy:
		if len(c.TrustedProxies) == 0 {
			return nil, fmt.Errorf("AUTH_MODE=proxy : TRUSTED_PROXIES est nécessaire (adresse du reverse proxy)")
		}
		info.Proxy = &ProxyInfo{LoginURL: c.ProxyLoginURL, LogoutURL: c.ProxyLogoutURL}
		return newProxy(c, info), nil
	case ModeLocal:
		return newLocal(c, info, log)
	}
	return nil, fmt.Errorf("AUTH_MODE : %q inconnu (none, oidc, proxy, local)", c.Mode)
}

// None : pas de comptes.
type None struct{}

func (None) User(*http.Request) *User { return nil }
func (None) Info() Info               { return Info{Mode: ModeNone, GuestPlay: true} }

// Mounter : une authentification qui sert ses propres pages (mode local). Le
// jeu les monte sur son routeur : if m, ok := a.(auth.Mounter); ok { m.Mount(mux) }.
type Mounter interface {
	Mount(mux *http.ServeMux)
}

// Func adapte une fonction en Authenticator, pour les tests des jeux.
type Func func(r *http.Request) *User

func (f Func) User(r *http.Request) *User { return f(r) }
func (f Func) Info() Info                 { return Info{Mode: "test", GuestPlay: true} }

// Bearer lit le jeton d'accès : en-tête Authorization, ou ?access_token= (le
// navigateur ne peut pas poser d'en-tête sur un WebSocket).
func Bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return r.URL.Query().Get("access_token")
}
