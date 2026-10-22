"""
VulnShop - application web pedagogique FICTIVE et VOLONTAIREMENT VULNERABLE,
inspiree de projets connus (DVWA, OWASP Juice Shop, WebGoat).

Objectif : s'entrainer a reperer/exploiter puis corriger des vulnerabilites
classiques (OWASP Top 10) dans un labo local, jetable, sans donnees reelles.

!!! A LANCER UNIQUEMENT EN LOCAL (Docker). NE JAMAIS DEPLOYER SUR INTERNET. !!!

Chaque faille est commentee "VULN n" avec son type (CWE / OWASP).
Les correctifs sont dans SOLUTIONS.md (a lire seulement apres avoir cherche).
"""
import os
import sqlite3

from flask import Flask, g, redirect, render_template_string, request, session

app = Flask(__name__)

# VULN-1 (CWE-798 Hardcoded secret) : cle de session fixe et triviale.
# Un attaquant qui la devine/la trouve dans le repo peut forger des sessions.
app.secret_key = "vulnshop-dev-secret"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "shop.db")
NOTES_DIR = os.path.join(BASE_DIR, "notes")  # fichiers texte "notes de commande"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(NOTES_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price REAL
        );
        """
    )
    # Mots de passe stockes en clair : VULN-2 (CWE-256) volontaire, pour la demo.
    db.executemany(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        [
            ("alice", "alice123", 0),
            ("bob", "bobpassword", 0),
            ("admin", "SuperAdmin2024!", 1),
        ],
    )
    db.executemany(
        "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
        [
            ("Maquette avion 1/48", "Kit plastique a monter", 24.90),
            ("Peinture acrylique", "Pot 17ml", 3.50),
            ("Pinceau fin", "Pour details", 5.20),
        ],
    )
    db.commit()
    db.close()
    for name, content in [
        ("1.txt", "Commande #1 (alice): 2x peinture acrylique.\n"),
        ("2.txt", "Commande #2 (bob): 1x maquette avion 1/48.\n"),
    ]:
        with open(os.path.join(NOTES_DIR, name), "w") as f:
            f.write(content)


LAYOUT = """
<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>VulnShop (labo)</title>
<style>
body{font-family:sans-serif;max-width:700px;margin:40px auto;color:#222}
nav a{margin-right:12px}
.banner{background:#fee;border:1px solid #c33;padding:8px;margin-bottom:16px;font-size:14px}
input{display:block;margin:6px 0;padding:4px}
.product{border-bottom:1px solid #ddd;padding:8px 0}
</style></head><body>
<div class="banner">Labo d'entrainement VOLONTAIREMENT vulnerable. Usage local uniquement.</div>
<nav>
<a href="/">Accueil</a>
<a href="/search">Recherche</a>
<a href="/login">Connexion</a>
<a href="/notes/1.txt">Exemple note</a>
</nav>
<hr>
{{ body|safe }}
</body></html>
"""


def render(body):
    return render_template_string(LAYOUT, body=body)


@app.route("/")
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    rows = "".join(
        f'<div class="product"><b>{p["name"]}</b> - {p["price"]}EUR'
        f'<br><a href="/product/{p["id"]}">voir</a></div>'
        for p in products
    )
    return render(f"<h1>Catalogue</h1>{rows}")


@app.route("/product/<int:pid>")
def product(pid):
    db = get_db()
    # VULN-3 (CWE-89 SQL Injection) : construction de requete par concatenation.
    # pid vient de l'URL mais la meme fonction de recherche plus bas est bien pire.
    row = db.execute(f"SELECT * FROM products WHERE id = {pid}").fetchone()
    if not row:
        return render("<p>Introuvable.</p>"), 404
    return render(f"<h1>{row['name']}</h1><p>{row['description']}</p><p>{row['price']} EUR</p>")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    results = []
    error = None
    if q:
        try:
            # VULN-4 (CWE-89 SQL Injection, point d'entree principal) :
            # f-string directement dans la requete SQL, aucune parametrisation.
            # Essaie par ex: q = ' OR '1'='1  ou une UNION SELECT.
            query = f"SELECT name, description, price FROM products WHERE name LIKE '%{q}%'"
            results = db.execute(query).fetchall()
        except sqlite3.Error as e:
            error = str(e)
    # VULN-5 (CWE-79 XSS reflechi) : q est reinjecte tel quel dans le HTML.
    # Essaie par ex: q = <script>alert(1)</script>
    body = f"""
    <h1>Recherche</h1>
    <form><input name="q" value="{q}" placeholder="nom du produit"><button>Chercher</button></form>
    <p>Vous avez cherche : {q}</p>
    """
    if error:
        body += f"<p style='color:red'>Erreur SQL : {error}</p>"
    for r in results:
        body += f'<div class="product"><b>{r["name"]}</b> - {r["price"]}EUR<br>{r["description"]}</div>'
    return render(body)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # VULN-6 (CWE-89 SQL Injection sur l'authentification) :
        # concatenation directe -> bypass possible avec  admin' --
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            user = db.execute(query).fetchone()
        except sqlite3.Error as e:
            return render(f"<p style='color:red'>Erreur SQL: {e}</p>")
        if user:
            session["user"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            return redirect("/account")
        error = "Identifiants invalides."
    body = f"""
    <h1>Connexion</h1>
    {'<p style="color:red">' + error + '</p>' if error else ''}
    <form method="post">
      <input name="username" placeholder="utilisateur">
      <input name="password" type="password" placeholder="mot de passe">
      <button>Se connecter</button>
    </form>
    <p><small>Comptes de demo : alice/alice123, bob/bobpassword, admin/SuperAdmin2024!</small></p>
    """
    return render(body)


@app.route("/account")
def account():
    # VULN-7 (CWE-862 controle d'acces manquant) : on ne vérifie meme pas
    # session["user"], on se contente de lire un cookie non signe custom.
    username = request.cookies.get("username") or session.get("user")
    if not username:
        return redirect("/login")
    is_admin = session.get("is_admin", False)
    admin_panel = ""
    if is_admin:
        admin_panel = "<p><a href='/admin'>Panneau admin</a></p>"
    # Le cookie "username" (non signe) permet l'usurpation : essaie de le
    # changer en "admin" dans les outils dev du navigateur.
    return render(f"<h1>Bonjour {username}</h1>{admin_panel}")


@app.route("/admin")
def admin():
    # VULN-8 (CWE-862) : controle d'acces cote client uniquement (pas de
    # verification serveur serieuse) + IDOR potentiel sur /notes/<fichier>.
    if not session.get("is_admin"):
        return render("<p>Acces reserve a l'admin. (mais verifie /admin?bypass=1 ;) )</p>"), 403
    db = get_db()
    users = db.execute("SELECT username, password, is_admin FROM users").fetchall()
    rows = "".join(f"<tr><td>{u['username']}</td><td>{u['password']}</td><td>{u['is_admin']}</td></tr>" for u in users)
    return render(f"<h1>Admin</h1><table border=1><tr><th>user</th><th>pass</th><th>admin</th></tr>{rows}</table>")


@app.route("/notes/<path:filename>")
def notes(filename):
    # VULN-9 (CWE-22 Path Traversal) : le nom de fichier n'est pas valide,
    # permet de sortir du dossier notes/ avec ../../..
    path = os.path.join(NOTES_DIR, filename)
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
    except OSError:
        return render("<p>Fichier introuvable.</p>"), 404
    return render(f"<h1>{filename}</h1><pre>{content}</pre>")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
    # VULN-10 (CWE-489) : debug=True en "production" -> debugger Werkzeug
    # exploitable (execution de code) si jamais expose publiquement.
