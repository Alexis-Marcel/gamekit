# gamekit

Briques communes aux jeux en ligne [Orapa](https://github.com/alexis-marcel/orapa),
[Coda](https://github.com/alexis-marcel/coda) et [Gemline](https://github.com/alexis-marcel/gemline).
Chaque jeu reste autonome : il fixe sa version de gamekit, et son image Docker contient tout.

## auth : comptes, au choix de celui qui héberge

Les comptes sont facultatifs : on joue en invité, un compte sert à garder ses parties.
La méthode se choisit par variables d'environnement, à la manière des apps *arr :

| Variable | Valeurs | Défaut |
|---|---|---|
| `AUTH_MODE` | `none` : pas de comptes ; `oidc` : un fournisseur OIDC (Authentik, Keycloak, Authelia, Google…) ; `proxy` : un reverse proxy qui authentifie déjà ; `local` : comptes intégrés au jeu | `oidc` si `OIDC_ISSUER` est donné, sinon `none` |
| `GUEST_PLAY` | `true` : on peut jouer sans compte ; `false` : compte exigé pour créer ou rejoindre une partie | `true` |
| `ACCOUNT_NAME` | nom du fournisseur dans l'interface (« Se connecter avec … ») | vide : « Se connecter » |
| `OIDC_ISSUER` | URL de l'émetteur (avec `/.well-known/openid-configuration`) | |
| `OIDC_CLIENT_ID` | client public (code + PKCE) déclaré chez le fournisseur | le nom du jeu |
| `OIDC_AUDIENCE` | audience attendue dans les jetons | `OIDC_CLIENT_ID` |
| `TRUSTED_PROXIES` | mode `proxy` : adresses ou plages du reverse proxy, séparées par des virgules (obligatoire) | |
| `PROXY_USER_HEADER` | en-tête de l'identifiant | `Remote-User` |
| `PROXY_NAME_HEADER` | en-tête du nom affiché | `Remote-Name` |
| `PROXY_EMAIL_HEADER` | en-tête de l'e-mail (facultatif, pour les jeux qui s'en servent) | `Remote-Email` |
| `PROXY_LOGIN_URL`, `PROXY_LOGOUT_URL` | pages de connexion et de déconnexion du proxy, pour les boutons de l'interface | aucun bouton |
| `SIGNUP` | mode `local` : `open` (libre), `invite` (sur lien d'un administrateur) ou `closed` | `invite` |

En mode `oidc`, le front se connecte lui-même et envoie le jeton d'accès (`Authorization: Bearer`,
ou `?access_token=` pour un WebSocket). Le serveur le vérifie par la JWKS du fournisseur, en épinglant
l'émetteur et l'audience : un jeton émis pour une autre application est refusé.

```go
cfg, err := auth.FromEnv(os.Getenv, "orapa")
a, err := auth.New(ctx, cfg, log)
u := a.User(r)      // nil : invité
info := a.Info()    // à servir au front dans /api/config
```

En mode `proxy`, le reverse proxy authentifie et pose l'identité dans un en-tête : `Remote-User` et `Remote-Name`
pour Authelia, `X-authentik-username` et `X-authentik-name` pour le forward auth d'Authentik,
`Tailscale-User-Login` et `Tailscale-User-Name` pour Tailscale Serve. L'en-tête n'est cru que si la connexion
elle-même vient d'une adresse de `TRUSTED_PROXIES` (jamais d'après `X-Forwarded-For`) : le jeu ne doit être
joignable que par le proxy, sinon n'importe qui pourrait se faire passer pour quelqu'un. Changer de mode
change les identifiants : les parties déjà jouées restent liées aux anciens comptes.

En mode `local`, les comptes vivent dans la base du jeu (tables `auth_*`, SQLite ou Postgres avec `SQLStore`) :
un compte d'un jeu n'est pas un compte d'un autre ; pour partager des comptes entre plusieurs jeux, passer par
`oidc`. Les pages (connexion, inscription, compte, administration, nouveau mot de passe) sont servies sous
`/compte/` par le module lui-même, sans JavaScript, aux couleurs que le jeu donne (`Theme`). Tant qu'il n'existe
aucun compte, la première inscription est ouverte et ce compte est administrateur ; il crée ensuite les liens
d'invitation et les liens de nouveau mot de passe.

- Mots de passe : argon2id (paramètres OWASP), 10 caractères au moins ; même temps de réponse que le compte
  existe ou non.
- Session : jeton aléatoire dans un cookie `HttpOnly`, `SameSite=Lax` ; la base n'en garde que le SHA-256.
- Formulaires refusés s'ils ne viennent pas du site (`Origin`), et requêtes du jeu venues d'un autre site
  traitées en invité.
- Tentatives limitées : 5 par minute pour un même compte, 30 par adresse.

```go
store, err := auth.NewSQLStore(ctx, db, auth.SQLite)
cfg.LocalStore, cfg.Theme = store, auth.Theme{Title: "Orapa", Accent: "#3e7bfa"}
a, err := auth.New(ctx, cfg, log)
if m, ok := a.(auth.Mounter); ok {
	m.Mount(mux) // pages /compte/
}
```

## secure : en-têtes de sécurité

`secure.Headers` enveloppe le handler du jeu et pose sur chaque réponse `X-Content-Type-Options: nosniff`,
`X-Frame-Options: SAMEORIGIN` et une CSP `frame-ancestors 'self'` (le jeu ne s'affiche pas dans le cadre d'un
autre site ; il garde ses propres iframes, dont celle du renouvellement silencieux OIDC),
`Referrer-Policy: strict-origin-when-cross-origin`, et HSTS (un an) quand la requête arrive en HTTPS, directement
ou d'après `X-Forwarded-Proto`. Un handler peut remplacer un de ces en-têtes.

```go
httpSrv := &http.Server{Handler: secure.Headers(srv.Handler())}
```

## portal : la barre d'un portail (facultative)

Quand un jeu fait partie d'un ensemble d'applications (un portail maison, par exemple), une barre discrète
au-dessus du jeu ramène à l'accueil du portail et au profil de la personne. Sans `PORTAL_URL`, pas de barre.

| Variable | Rôle |
|---|---|
| `PORTAL_URL` | accueil du portail (active la barre) |
| `PORTAL_NAME` | nom affiché (défaut : l'hôte de `PORTAL_URL`) |
| `PORTAL_ICON` | icône du portail (URL d'une image) |
| `PROFILE_URL` | page de profil, affichée aux personnes connectées |

```go
cfg["portal"] = portal.FromEnv(os.Getenv) // nil sans portail, à servir dans /api/config
```

## Licence

MIT
