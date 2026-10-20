// Package portal décrit, facultativement, le portail dont un jeu fait partie :
// une barre discrète au-dessus du jeu ramène à son accueil et au profil de la
// personne. Sans PORTAL_URL, pas de barre : le jeu vit seul.
package portal

import (
	"net/url"
	"strings"
)

// Info est servi tel quel au front (dans /api/config) ; nil sans portail.
type Info struct {
	URL        string `json:"url"`
	Name       string `json:"name"`
	Icon       string `json:"icon,omitempty"`
	ProfileURL string `json:"profileUrl,omitempty"`
}

// FromEnv lit PORTAL_URL, PORTAL_NAME (défaut : l'hôte de PORTAL_URL),
// PORTAL_ICON et PROFILE_URL. Seules les adresses http(s) sont gardées : elles
// finissent dans des liens et des images de la page.
func FromEnv(getenv func(string) string) *Info {
	u := web(getenv("PORTAL_URL"))
	if u == "" {
		return nil
	}
	name := strings.TrimSpace(getenv("PORTAL_NAME"))
	if name == "" {
		p, _ := url.Parse(u)
		name = p.Host
	}
	return &Info{URL: u, Name: name, Icon: web(getenv("PORTAL_ICON")), ProfileURL: web(getenv("PROFILE_URL"))}
}

func web(s string) string {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return u.String()
}
