import re
import os
import shutil
import sqlite3
import subprocess  # nosec B404 - usado únicamente con lista de args (sin shell=True) y ruta absoluta resuelta abajo

from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
)

from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired

import bcrypt

app = Flask(__name__)

# ===========================
# Configuración segura
# ===========================

# Sin valor por defecto: si no está definida, la app no debe arrancar.
app.secret_key = os.environ["SECRET_KEY"]

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# Protección CSRF global para TODOS los formularios POST,
# no solo los que usan FlaskForm explícitamente
csrf = CSRFProtect(app)

# Formato válido de host para /ping (evita inyección de flags tipo "-f", "-c 100", etc.)
HOST_RE = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")

# Ruta absoluta del binario 'ping', resuelta una sola vez al arrancar
# (evita B607: no confiar en el PATH del sistema en cada llamada)
PING_PATH = shutil.which("ping")
if PING_PATH is None:
    raise RuntimeError("No se encontró el binario 'ping' en el sistema.")


# ===========================
# Base de datos
# ===========================

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


# ===========================
# Autenticación
# ===========================

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


# ===========================
# Formularios
# ===========================

class LoginForm(FlaskForm):
    username = StringField("Usuario", validators=[DataRequired()])
    password = PasswordField("Contraseña", validators=[DataRequired()])


class PingForm(FlaskForm):
    host = StringField("Host", validators=[DataRequired()])


class DownloadForm(FlaskForm):
    filename = StringField("Archivo", validators=[DataRequired()])


class ProfileForm(FlaskForm):
    password = PasswordField("Nueva contraseña", validators=[DataRequired()])


# ===========================
# Página principal
# ===========================

@app.route("/")
def index():
    return render_template("index.html")


# ===========================
# robots.txt / sitemap.xml
# ===========================

@app.route("/robots.txt")
def robots():
    return app.response_class(
        "User-agent: *\nDisallow: /\n",
        mimetype="text/plain"
    )


@app.route("/sitemap.xml")
def sitemap():
    return ("", 404)


# ===========================
# Login seguro
# ===========================

@app.route("/login", methods=["GET", "POST"])
def login():

    form = LoginForm()

    if form.validate_on_submit():

        username = form.username.data
        password = form.password.data

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password FROM users WHERE username=?",
            (username,)
        )

        row = cursor.fetchone()
        conn.close()

        if row:

            stored_password = row["password"].encode()

            if bcrypt.checkpw(password.encode(), stored_password):

                session["user"] = username
                session.permanent = True

                return redirect("/dashboard")

        return render_template(
            "login.html",
            form=form,
            error="Usuario o contraseña incorrectos"
        )

    return render_template("login.html", form=form)


# ===========================
# Dashboard
# ===========================

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session["user"])


# ===========================
# Logout
# ===========================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ===========================
# Ping seguro
# ===========================

@app.route("/ping", methods=["GET", "POST"])
@login_required
def ping():

    form = PingForm()
    result = ""

    if form.validate_on_submit():

        host = form.host.data

        if not HOST_RE.match(host) or host.startswith("-"):
            result = "Host inválido."
        else:
            try:
                result = subprocess.run( # nosec B603
                    [PING_PATH, "-c", "1", "--", host],
                    capture_output=True,
                    text=True,
                    timeout=5
                ).stdout
            except Exception as e:
                result = str(e)

    return render_template("ping.html", form=form, result=result)


# ===========================
# Descarga segura
# ===========================

@app.route("/download", methods=["GET", "POST"])
@login_required
def download():

    form = DownloadForm()
    content = ""

    if form.validate_on_submit():

        filename = form.filename.data

        base_path = os.path.abspath("uploads") + os.sep

        requested_path = os.path.abspath(
            os.path.join(base_path, filename)
        )

        if not requested_path.startswith(base_path):
            content = "Acceso denegado."
        else:
            try:
                with open(requested_path, "r") as f:
                    content = f.read()
            except Exception:
                content = "El archivo no existe."

    return render_template("download.html", form=form, content=content)


# ===========================
# Perfil
# ===========================

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():

    form = ProfileForm()
    hashed = ""

    if form.validate_on_submit():

        password = form.password.data

        hashed = bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        ).decode()

    return render_template("profile.html", form=form, hashed=hashed)


# ===========================
# Búsqueda
# ===========================

@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    return render_template("search.html", query=query)


# ===========================
# Páginas de error
# ===========================

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.exception("Error interno no controlado")
    return render_template("500.html"), 500


# ===========================
# Cabeceras de seguridad
# ===========================

@app.after_request
def security_headers(response):

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin"
    response.headers["Permissions-Policy"] = "geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"

    # Ocultar la versión real del servidor
    response.headers["Server"] = "WebServer"

    return response


# ===========================
# Inicio de la aplicación
# ===========================

if __name__ == "__main__":

    # Este bloque solo se usa para pruebas locales con "python app.py".
    from werkzeug.serving import WSGIRequestHandler

    class CustomRequestHandler(WSGIRequestHandler):
        def version_string(self):
            return "WebServer"

    app.run(
        host="0.0.0.0",  # nosec B104 - necesario para exponer el contenedor Docker; solo se usa en este bloque de desarrollo/CI, producción real corre tras Gunicorn
        port=5000,
        debug=False,
        request_handler=CustomRequestHandler
    )
