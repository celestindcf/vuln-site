# VulnShop — labo web volontairement vulnérable

VulnShop est une mini-boutique **fictive** (Flask + SQLite), créée uniquement
pour s'entraîner à repérer et exploiter des vulnérabilités web classiques
(OWASP Top 10), dans l'esprit de projets connus comme **DVWA**,
**OWASP Juice Shop** ou **WebGoat**.

> ⚠️ **À usage strictement local / pédagogique.**
> Ne déployez jamais ce projet sur un serveur accessible depuis Internet,
> même "pour rire" ou "juste deux minutes". Le code contient des failles
> exploitables à distance (RCE possible via le mode debug, injections SQL,
> etc.). Vous êtes responsable de l'usage que vous en faites : entraînez-vous
> uniquement sur vos propres machines / environnements isolés.

## Lancer le labo

Avec Docker (recommandé) :

```bash
docker compose up --build
```

L'application est accessible sur `http://127.0.0.1:5000` (bind local
uniquement, pas d'exposition réseau par défaut).

Sans Docker :

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Ce qu'il y a à trouver

Le code contient 10 vulnérabilités volontaires, commentées `VULN-n` dans
`app.py`. Objectif : les repérer en lisant/testant l'appli, les exploiter,
puis proposer un correctif. Sans spoiler, les familles couvertes :

- Injection SQL (plusieurs points d'entrée, dont le login)
- XSS réfléchi
- Contrôle d'accès cassé / IDOR
- Path traversal (lecture de fichiers arbitraires)
- Mots de passe stockés en clair
- Secret de session codé en dur
- Cookie d'identité non signé, falsifiable
- Mode debug actif (exécution de code à distance dans Werkzeug)

**Conseil** : utilisez Burp Suite / OWASP ZAP, ou simplement `curl` et les
outils de dev du navigateur, pour explorer les requêtes et réponses.

Les corrigés détaillés (faille + preuve d'exploitation + correctif) sont
dans [`SOLUTIONS.md`](SOLUTIONS.md) — à ne consulter qu'après avoir cherché
par vous-même.

## Publier ce repo sur GitHub

```bash
cd vulnshop
git init
git add .
git commit -m "VulnShop: labo pedagogique volontairement vulnerable"
git branch -M main
git remote add origin https://github.com/<votre-compte>/vulnshop.git
git push -u origin main
```

Pensez à mettre le dépôt en **privé** si vous ne voulez pas que d'autres
voient les solutions avant d'avoir cherché, et ajoutez un bandeau
d'avertissement bien visible dans la description GitHub du repo (déjà fait
dans ce README, à garder).

## Licence / cadre

Projet pédagogique, à adapter librement pour votre propre entraînement.
Ne contient aucune donnée réelle (utilisateurs, mots de passe, produits —
tout est inventé).
