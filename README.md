# gamekit

Briques communes aux jeux en ligne [Orapa](https://github.com/alexis-marcel/orapa),
[Coda](https://github.com/alexis-marcel/coda) et [Gemline](https://github.com/alexis-marcel/gemline).
Chaque jeu reste autonome : il fixe sa version de gamekit, et son image Docker contient tout.

## auth : comptes, au choix de celui qui héberge

Les comptes sont facultatifs : on joue en invité, un compte sert à garder ses parties.
La méthode se choisit par variables d'environnement, à la manière des apps *arr :

| Variable | Valeurs | Défaut |
|---|---|---|
| `AUTH_MODE` | `none` : pas de comptes ; `oidc` : un fournisseur OIDC (Authentik, Keycloak, Authelia, Google…) ; `proxy` : un reverse proxy qui authentifie déjà | `oidc` si `OIDC_ISSUER` est donné, sinon `none` |
| `GUEST_PLAY` | `true` : on peut jouer sans compte ; `false` : compte exigé pour créer ou rejoindre une partie | `true` |
| `ACCOUNT_NAME` | nom du fournisseur dans l'interface (« Se connecter avec … ») | vide : « Se connecter » |
| `OIDC_ISSUER` | URL de l'émetteur (avec `/.well-known/openid-configuration`) | |
| `OIDC_CLIENT_ID` | client public (code + PKCE) déclaré chez le fournisseur | le nom du jeu |
| `OIDC_AUDIENCE` | audience attendue dans les jetons | `OIDC_CLIENT_ID` |
| `TRUSTED_PROXIES` | mode `proxy` : adresses ou plages du reverse proxy, séparées par des virgules (obligatoire) | |
| `PROXY_USER_HEADER` | en-tête de l'identifiant | `Remote-User` |
| `PROXY_NAME_HEADER` | en-tête du nom affiché | `Remote-Name` |
| `PROXY_LOGIN_URL`, `PROXY_LOGOUT_URL` | pages de connexion et de déconnexion du proxy, pour les boutons de l'interface | aucun bouton |

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

À venir : `local` (comptes intégrés au jeu).

## Licence

MIT
