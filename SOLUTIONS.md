# Solutions — VulnShop

⚠️ Essayez de trouver les failles par vous-même avant de lire ceci.

## VULN-1 — Secret de session codé en dur (CWE-798)
`app.secret_key = "vulnshop-dev-secret"` est fixe et visible dans le code
source. Quiconque le connaît peut forger/modifier des cookies de session
Flask signés avec cette clé (ex. avec `flask-unsign`).
**Correctif** : générer une clé aléatoire forte (`secrets.token_hex(32)`),
la charger depuis une variable d'environnement, jamais la committer.

## VULN-2 — Mots de passe en clair (CWE-256)
Les mots de passe sont stockés tels quels en base.
**Correctif** : hacher avec un algorithme dédié (bcrypt, argon2, scrypt),
jamais SHA/MD5 seuls (pas de sel = rainbow tables).

## VULN-3 / VULN-4 / VULN-6 — Injections SQL (CWE-89)
Les requêtes sont construites par f-string / concaténation :
- `/product/<pid>` : `f"SELECT * FROM products WHERE id = {pid}"`
- `/search?q=` : `f"... WHERE name LIKE '%{q}%'"` → essayez
  `q = ' UNION SELECT username, password, 1 FROM users --`
- `/login` : `f"... WHERE username='{u}' AND password='{p}'"` → essayez
  `username = admin' -- ` (avec un espace final) pour contourner
  l'authentification sans connaître le mot de passe.

**Correctif** : toujours utiliser des requêtes paramétrées :
```python
db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```
Jamais de f-string/`%`/`.format()` dans du SQL.

## VULN-5 — XSS réfléchi (CWE-79)
`/search?q=<script>alert(1)</script>` est renvoyé tel quel dans le HTML.
**Correctif** : échapper toute donnée utilisateur avant injection HTML
(Jinja2 le fait automatiquement avec `{{ q }}` au lieu de f-string +
`|safe`), ou utiliser `markupsafe.escape()`.

## VULN-7 / VULN-8 — Contrôle d'accès cassé (CWE-862)
- `/account` lit un cookie `username` non signé : en le changeant via les
  outils dev du navigateur, on peut usurper n'importe quel compte sans
  mot de passe.
- `/admin` ne vérifie que `session["is_admin"]`, lui-même positionné à
  partir d'une injection SQL possible côté `/login` (VULN-6) — un
  attaquant peut se connecter en tant qu'admin sans le mot de passe.

**Correctif** : ne jamais faire confiance à un cookie non signé pour
l'identité ; s'appuyer uniquement sur `session` (signée par Flask avec un
vrai secret) ; vérifier les droits côté serveur à chaque requête
sensible, pas seulement côté client/UI.

## VULN-9 — Path traversal (CWE-22)
`/notes/../../../../etc/passwd` (encodé en URL si besoin :
`%2e%2e%2f`) permet de sortir du dossier `notes/` et de lire des fichiers
arbitraires lisibles par le process.
**Correctif** : valider que le chemin résolu reste bien sous `NOTES_DIR`
(`os.path.realpath` + vérification de préfixe), ou servir les fichiers via
`flask.send_from_directory` qui fait cette vérification.

## VULN-10 — Mode debug activé (CWE-489)
`debug=True` active le débogueur interactif Werkzeug. S'il est exposé,
un attaquant qui déclenche une exception accède à une console Python
**avec exécution de code arbitraire** sur le serveur.
**Correctif** : `debug=False` en dehors du développement strictement
local, et ne jamais exposer l'appli Flask de dev directement (utiliser un
vrai serveur WSGI comme gunicorn derrière un reverse proxy).
