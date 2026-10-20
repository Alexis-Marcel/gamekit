package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// provider est un faux fournisseur OIDC : découverte, JWKS et une clé de signature.
type provider struct {
	*httptest.Server
	key *rsa.PrivateKey
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": p.URL + "/", "jwks_uri": p.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

func (p *provider) token(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	base := jwt.MapClaims{"iss": p.URL + "/", "aud": "jeu", "sub": "u1", "name": "Alice", "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, base)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func request(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestOIDC(t *testing.T) {
	p := newProvider(t)
	a, err := New(context.Background(), Config{OIDCIssuer: p.URL + "/", OIDCClientID: "jeu", AccountName: "Eriphe", GuestPlay: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	info := a.Info()
	if info.Mode != ModeOIDC || info.OIDC == nil || info.OIDC.ClientID != "jeu" || info.AccountName != "Eriphe" {
		t.Fatalf("info %+v", info)
	}
	if u := a.User(request(p.token(t, p.key, nil))); u == nil || u.ID != "u1" || u.Name != "Alice" {
		t.Fatalf("jeton valide : %+v", u)
	}
	if u := a.User(request(p.token(t, p.key, jwt.MapClaims{"name": nil, "preferred_username": "alice"}))); u == nil || u.Name != "alice" {
		t.Fatalf("nom d'utilisateur à défaut du nom : %+v", u)
	}
	ws := httptest.NewRequest(http.MethodGet, "/ws?access_token="+p.token(t, p.key, nil), nil)
	if a.User(ws) == nil {
		t.Fatal("jeton du WebSocket refusé")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	refused := map[string]string{
		"sans jeton":         "",
		"autre application":  p.token(t, p.key, jwt.MapClaims{"aud": "autre"}),
		"autre émetteur":     p.token(t, p.key, jwt.MapClaims{"iss": "https://ailleurs/"}),
		"expiré":             p.token(t, p.key, jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}),
		"sans sub":           p.token(t, p.key, jwt.MapClaims{"sub": nil}),
		"signé par un autre": p.token(t, other, nil),
		"pas un jeton":       "n'importe quoi",
	}
	for name, tok := range refused {
		if u := a.User(request(tok)); u != nil {
			t.Errorf("%s : accepté comme %+v", name, u)
		}
	}
}

func TestOIDCUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := New(ctx, Config{Mode: ModeOIDC, OIDCIssuer: "http://127.0.0.1:1/", OIDCClientID: "jeu"}, nil); err == nil {
		t.Fatal("fournisseur injoignable accepté")
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestFromEnv(t *testing.T) {
	c, err := FromEnv(env(nil), "orapa")
	if err != nil || c.Mode != "" || !c.GuestPlay || c.OIDCClientID != "orapa" {
		t.Fatalf("défauts %+v %v", c, err)
	}
	c, err = FromEnv(env(map[string]string{"AUTH_MODE": " OIDC ", "GUEST_PLAY": "false", "OIDC_CLIENT_ID": "x", "ACCOUNT_NAME": " Eriphe "}), "orapa")
	if err != nil || c.Mode != ModeOIDC || c.GuestPlay || c.OIDCClientID != "x" || c.AccountName != "Eriphe" {
		t.Fatalf("lu %+v %v", c, err)
	}
	if _, err := FromEnv(env(map[string]string{"GUEST_PLAY": "peut-être"}), "orapa"); err == nil {
		t.Fatal("GUEST_PLAY invalide accepté")
	}
}

func TestNewModes(t *testing.T) {
	ctx := context.Background()
	a, err := New(ctx, Config{GuestPlay: true}, nil)
	if err != nil || a.Info().Mode != ModeNone || a.User(request("x")) != nil {
		t.Fatalf("sans fournisseur : %v %v", a, err)
	}
	for name, c := range map[string]Config{
		"personne ne joue": {Mode: ModeNone, GuestPlay: false},
		"oidc sans issuer": {Mode: ModeOIDC, OIDCClientID: "jeu", GuestPlay: true},
		"mode inconnu":     {Mode: "ldap", GuestPlay: true},
	} {
		if _, err := New(ctx, c, nil); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}
