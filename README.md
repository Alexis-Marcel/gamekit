# gamekit

Briques communes aux jeux en ligne [Orapa](https://github.com/alexis-marcel/orapa),
[Coda](https://github.com/alexis-marcel/coda) et [Gemline](https://github.com/alexis-marcel/gemline).
Chaque jeu reste autonome : il fixe sa version de gamekit, et son image Docker contient tout.

## auth : comptes, au choix de celui qui héberge

Les comptes sont facultatifs : on joue en invité, un compte sert à garder ses parties.
La méthode se choisit par variables d'environnement, à la manière des apps *arr :

| Variable | Valeurs | Défaut |
|---|---|---|
| `AUTH_MODE` | `none` : pas de comptes ; `oidc` : un fournisseur OIDC (Authentik, Keycloak, Authelia, Google…) | `oidc` si `OIDC_ISSUER` est donné, sinon `none` |
| `GUEST_PLAY` | `true` : on peut jouer sans compte ; `false` : compte exigé pour créer ou rejoindre une partie | `true` |
| `ACCOUNT_NAME` | nom du fournisseur dans l'interface (« Se connecter avec … ») | vide : « Se connecter » |
| `OIDC_ISSUER` | URL de l'émetteur (avec `/.well-known/openid-configuration`) | |
| `OIDC_CLIENT_ID` | client public (code + PKCE) déclaré chez le fournisseur | le nom du jeu |
| `OIDC_AUDIENCE` | audience attendue dans les jetons | `OIDC_CLIENT_ID` |

En mode `oidc`, le front se connecte lui-même et envoie le jeton d'accès (`Authorization: Bearer`,
ou `?access_token=` pour un WebSocket). Le serveur le vérifie par la JWKS du fournisseur, en épinglant
l'émetteur et l'audience : un jeton émis pour une autre application est refusé.

```go
cfg, err := auth.FromEnv(os.Getenv, "orapa")
a, err := auth.New(ctx, cfg, log)
u := a.User(r)      // nil : invité
info := a.Info()    // à servir au front dans /api/config
```

À venir : `proxy` (en-tête d'un reverse proxy de confiance) et `local` (comptes intégrés au jeu).

## Licence

MIT
