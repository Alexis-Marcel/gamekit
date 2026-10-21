// Package secure pose les en-têtes de sécurité communs à toutes les réponses
// d'un jeu : pas de devinette du type des fichiers, pas d'affichage dans le
// cadre d'un autre site (le jeu peut s'encadrer lui-même : le renouvellement
// silencieux OIDC passe par une iframe du même site), un référent réduit à
// l'origine hors du site, et HSTS quand le jeu est servi en HTTPS.
package secure

import (
	"net/http"
	"strings"
)

// HSTS : un an, sans includeSubDomains (le jeu ne décide pas pour les autres
// noms du domaine).
const hsts = "max-age=31536000"

// Headers enveloppe next. Un handler peut remplacer un en-tête (Set) : ils
// sont posés avant lui.
func Headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Content-Security-Policy", "frame-ancestors 'self'; base-uri 'self'; object-src 'none'")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if https(r) {
			h.Set("Strict-Transport-Security", hsts)
		}
		next.ServeHTTP(w, r)
	})
}

// https : la connexion est chiffrée, ou le proxy devant le jeu (tunnel,
// reverse proxy) dit l'avoir reçue en HTTPS. Un client qui ment sur
// X-Forwarded-Proto ne s'impose HSTS qu'à lui-même : les navigateurs ignorent
// cet en-tête sur une page en HTTP.
func https(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}
