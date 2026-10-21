package secure

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeaders(t *testing.T) {
	h := Headers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/compte/" {
			w.Header().Set("X-Frame-Options", "DENY")
		}
	}))
	get := func(path, proto string) http.Header {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Header()
	}

	got := get("/", "")
	if got.Get("X-Content-Type-Options") != "nosniff" || got.Get("X-Frame-Options") != "SAMEORIGIN" ||
		got.Get("Content-Security-Policy") == "" || got.Get("Referrer-Policy") == "" {
		t.Fatalf("en-têtes manquants : %v", got)
	}
	if got.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS en HTTP")
	}
	if get("/", "https").Get("Strict-Transport-Security") != hsts || get("/", "HTTPS, http").Get("Strict-Transport-Security") != hsts {
		t.Fatal("pas de HSTS derrière un proxy HTTPS")
	}
	if get("/", "http").Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS derrière un proxy HTTP")
	}
	if get("/compte/", "").Get("X-Frame-Options") != "DENY" {
		t.Fatal("le handler ne peut pas remplacer un en-tête")
	}
}
