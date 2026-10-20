package portal

import "testing"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestFromEnv(t *testing.T) {
	if FromEnv(env(nil)) != nil {
		t.Fatal("portail sans PORTAL_URL")
	}
	i := FromEnv(env(map[string]string{"PORTAL_URL": "https://eriphe.com", "PORTAL_ICON": "https://eriphe.com/favicon.svg", "PROFILE_URL": "https://eriphe.com/profil"}))
	if i == nil || i.Name != "eriphe.com" || i.Icon == "" || i.ProfileURL != "https://eriphe.com/profil" {
		t.Fatalf("portail %+v", i)
	}
	i = FromEnv(env(map[string]string{"PORTAL_URL": " https://eriphe.com ", "PORTAL_NAME": " Eriphe ", "PORTAL_ICON": "javascript:alert(1)", "PROFILE_URL": "/profil"}))
	if i == nil || i.Name != "Eriphe" || i.Icon != "" || i.ProfileURL != "" {
		t.Fatalf("adresses non web gardées : %+v", i)
	}
	if FromEnv(env(map[string]string{"PORTAL_URL": "javascript:alert(1)"})) != nil {
		t.Fatal("PORTAL_URL non web accepté")
	}
}
