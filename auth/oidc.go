package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// OIDC : jeton d'accès d'un fournisseur OIDC dans Authorization: Bearer (ou
// ?access_token= pour le WebSocket). Le front se connecte lui-même (code + PKCE)
// avec les informations de Info().OIDC.
type OIDC struct {
	verifier *Verifier
	info     Info
	log      *slog.Logger
}

func (o *OIDC) Info() Info { return o.info }

func (o *OIDC) User(r *http.Request) *User {
	t := Bearer(r)
	if t == "" {
		return nil
	}
	u, err := o.verifier.Verify(t)
	if err != nil {
		o.log.Debug("jeton refusé", "err", err)
		return nil
	}
	return u
}

type tokenClaims struct {
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	jwt.RegisteredClaims
}

// Verifier vérifie les jetons d'accès d'un fournisseur OIDC.
type Verifier struct {
	keyfunc jwt.Keyfunc
}

// NewVerifier découvre la JWKS du fournisseur et épingle iss et aud : un jeton
// émis par le même fournisseur pour une autre application est refusé.
func NewVerifier(ctx context.Context, issuer, audience string) (*Verifier, error) {
	discovery := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("découverte OIDC : %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("découverte OIDC : HTTP %d", res.StatusCode)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("découverte OIDC : %w", err)
	}
	if doc.JWKSURI == "" {
		return nil, errors.New("découverte OIDC : pas de jwks_uri")
	}
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{doc.JWKSURI})
	if err != nil {
		return nil, fmt.Errorf("JWKS : %w", err)
	}
	return &Verifier{keyfunc: pinClaims(kf.Keyfunc, doc.Issuer, audience)}, nil
}

func pinClaims(kf jwt.Keyfunc, issuer, audience string) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		if iss, _ := t.Claims.GetIssuer(); iss != issuer {
			return nil, fmt.Errorf("émetteur inattendu %q", iss)
		}
		if audience != "" {
			aud, _ := t.Claims.GetAudience()
			if !slices.Contains(aud, audience) {
				return nil, fmt.Errorf("jeton émis pour une autre application que %q", audience)
			}
		}
		return kf(t)
	}
}

// Verify renvoie le compte d'un jeton valide.
func (v *Verifier) Verify(token string) (*User, error) {
	claims := &tokenClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, v.keyfunc)
	if err != nil {
		return nil, err
	}
	if !parsed.Valid || claims.Subject == "" {
		return nil, errors.New("jeton invalide")
	}
	name := strings.TrimSpace(claims.Name)
	if name == "" {
		name = strings.TrimSpace(claims.PreferredUsername)
	}
	return &User{ID: claims.Subject, Name: name}, nil
}
