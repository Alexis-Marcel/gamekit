// Package auth identifie le compte derrière une requête, selon une méthode
// choisie par celui qui héberge le jeu (AUTH_MODE), à la manière des apps *arr :
//
//   - none : pas de comptes, tout le monde joue en invité ;
//   - oidc : jeton d'accès d'un fournisseur OIDC (Authentik, Keycloak,
//     Authelia, Google…), vérifié par sa JWKS.
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
	"strings"
)

// User est un compte : ID est stable (le sub OIDC), Name est le nom affiché.
type User struct {
	ID   string
	Name string
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
	Mode        string    `json:"mode"`                  // none, oidc
	AccountName string    `json:"accountName,omitempty"` // « Se connecter avec … » ; vide : « Se connecter »
	GuestPlay   bool      `json:"guestPlay"`             // jouer sans compte est permis
	OIDC        *OIDCInfo `json:"oidc,omitempty"`
}

type OIDCInfo struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"clientId"`
}

const (
	ModeNone = "none"
	ModeOIDC = "oidc"
)

// Config est la configuration d'authentification d'un jeu.
type Config struct {
	Mode         string // vide : oidc si OIDCIssuer est donné, sinon none
	AccountName  string
	GuestPlay    bool
	OIDCIssuer   string
	OIDCClientID string
	OIDCAudience string // vide : OIDCClientID
}

// FromEnv lit AUTH_MODE, ACCOUNT_NAME, GUEST_PLAY (vrai par défaut), OIDC_ISSUER,
// OIDC_CLIENT_ID (défaut : clientID, le nom du jeu) et OIDC_AUDIENCE.
func FromEnv(getenv func(string) string, clientID string) (Config, error) {
	c := Config{
		Mode:         strings.ToLower(strings.TrimSpace(getenv("AUTH_MODE"))),
		AccountName:  strings.TrimSpace(getenv("ACCOUNT_NAME")),
		GuestPlay:    true,
		OIDCIssuer:   getenv("OIDC_ISSUER"),
		OIDCClientID: getenv("OIDC_CLIENT_ID"),
		OIDCAudience: getenv("OIDC_AUDIENCE"),
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
		info.OIDC = &OIDCInfo{Issuer: c.OIDCIssuer, ClientID: c.OIDCClientID}
		return &OIDC{verifier: v, info: info, log: log}, nil
	}
	return nil, fmt.Errorf("AUTH_MODE : %q inconnu (none, oidc)", c.Mode)
}

// None : pas de comptes.
type None struct{}

func (None) User(*http.Request) *User { return nil }
func (None) Info() Info              { return Info{Mode: ModeNone, GuestPlay: true} }

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
