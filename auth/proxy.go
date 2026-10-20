package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// Proxy : le reverse proxy a déjà authentifié la personne et pose son identité
// dans un en-tête (Remote-User pour Authelia, X-authentik-username pour le
// forward auth d'Authentik, Tailscale-User-Login pour Tailscale Serve…).
//
// L'en-tête n'est cru que si la connexion vient d'une adresse de
// TrustedProxies : n'importe qui d'autre pourrait l'écrire. On regarde
// l'adresse de la connexion elle-même, jamais X-Forwarded-For, que le client
// remplit comme il veut. Le jeu ne doit donc être joignable que par le proxy,
// ou TrustedProxies ne doit contenir que l'adresse du proxy.
type Proxy struct {
	userHeader, nameHeader string
	trusted                []netip.Prefix
	info                   Info
}

func newProxy(c Config, info Info) *Proxy {
	p := &Proxy{userHeader: c.ProxyUserHeader, nameHeader: c.ProxyNameHeader, trusted: c.TrustedProxies, info: info}
	if p.userHeader == "" {
		p.userHeader = "Remote-User"
	}
	if p.nameHeader == "" {
		p.nameHeader = "Remote-Name"
	}
	return p
}

func (p *Proxy) Info() Info { return p.info }

func (p *Proxy) User(r *http.Request) *User {
	if !p.fromTrusted(r) {
		return nil
	}
	id := clean(r.Header.Get(p.userHeader))
	if id == "" {
		return nil
	}
	name := clean(r.Header.Get(p.nameHeader))
	if name == "" {
		name = id
	}
	return &User{ID: id, Name: name}
}

func (p *Proxy) fromTrusted(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, t := range p.trusted {
		if t.Contains(addr) {
			return true
		}
	}
	return false
}

// clean garde une valeur d'en-tête lisible et courte (200 caractères au plus).
func clean(v string) string {
	v = strings.TrimSpace(v)
	if !utf8.ValidString(v) {
		return ""
	}
	if utf8.RuneCountInString(v) > 200 {
		v = string([]rune(v)[:200])
	}
	return v
}

// parsePrefix lit une plage (10.0.0.0/8) ou une adresse seule (192.168.1.2).
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
