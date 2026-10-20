package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func fromProxy(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestProxy(t *testing.T) {
	c, err := FromEnv(env(map[string]string{
		"AUTH_MODE":        "proxy",
		"TRUSTED_PROXIES":  "192.168.1.2, 10.0.0.0/8 ,fd00::/8",
		"PROXY_LOGIN_URL":  "https://auth.example/login",
		"PROXY_LOGOUT_URL": "https://auth.example/logout",
	}), "jeu")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if i := a.Info(); i.Mode != ModeProxy || i.Proxy == nil || i.Proxy.LoginURL != "https://auth.example/login" || i.Proxy.LogoutURL == "" {
		t.Fatalf("info %+v", i)
	}

	if u := a.User(fromProxy("192.168.1.2:4321", map[string]string{"Remote-User": "alice", "Remote-Name": "Alice Martin"})); u == nil || u.ID != "alice" || u.Name != "Alice Martin" {
		t.Fatalf("depuis le proxy : %+v", u)
	}
	if u := a.User(fromProxy("10.1.2.3:1", map[string]string{"Remote-User": " bob "})); u == nil || u.ID != "bob" || u.Name != "bob" {
		t.Fatalf("plage de confiance, sans nom : %+v", u)
	}
	if u := a.User(fromProxy("[::ffff:192.168.1.2]:1", map[string]string{"Remote-User": "alice"})); u == nil {
		t.Fatal("IPv4 dans une adresse IPv6 refusée")
	}
	if u := a.User(fromProxy("[fd12::1]:1", map[string]string{"Remote-User": "alice"})); u == nil {
		t.Fatal("plage IPv6 refusée")
	}
	refused := map[string]*http.Request{
		"hors des proxys de confiance": fromProxy("192.168.1.50:1", map[string]string{"Remote-User": "mallory"}),
		"X-Forwarded-For ignoré":       fromProxy("203.0.113.9:1", map[string]string{"Remote-User": "mallory", "X-Forwarded-For": "192.168.1.2"}),
		"sans en-tête":                 fromProxy("192.168.1.2:1", nil),
		"adresse illisible":            fromProxy("n'importe quoi", map[string]string{"Remote-User": "alice"}),
	}
	for name, r := range refused {
		if u := a.User(r); u != nil {
			t.Errorf("%s : accepté comme %+v", name, u)
		}
	}
}

func TestProxyHeaders(t *testing.T) {
	a, err := New(context.Background(), Config{Mode: ModeProxy, GuestPlay: true, ProxyUserHeader: "Tailscale-User-Login",
		ProxyNameHeader: "Tailscale-User-Name", TrustedProxies: mustPrefixes(t, "127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	u := a.User(fromProxy("127.0.0.1:1", map[string]string{"Tailscale-User-Login": "alice@example.com", "Tailscale-User-Name": "Alice", "Remote-User": "autre"}))
	if u == nil || u.ID != "alice@example.com" || u.Name != "Alice" {
		t.Fatalf("en-têtes choisis : %+v", u)
	}
}

func TestProxyConfig(t *testing.T) {
	if _, err := FromEnv(env(map[string]string{"TRUSTED_PROXIES": "192.168.1.300"}), "jeu"); err == nil {
		t.Fatal("adresse invalide acceptée")
	}
	if _, err := New(context.Background(), Config{Mode: ModeProxy, GuestPlay: true}, nil); err == nil {
		t.Fatal("mode proxy sans TRUSTED_PROXIES accepté")
	}
}

func mustPrefixes(t *testing.T, ss ...string) (out []netip.Prefix) {
	t.Helper()
	for _, s := range ss {
		p, err := parsePrefix(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}
