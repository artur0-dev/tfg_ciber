# Panel de Administración (Flask) — Versión Segura vs. Vulnerable

Proyecto de ejemplo con **dos versiones de la misma aplicación web** (Flask), usado como caso de estudio para comparar el efecto de un pipeline de **DevSecOps** en GitHub Actions:

- **`app-segura/`** — implementación corregida, con las vulnerabilidades mitigadas.
- **`app-vulnerable/`** — implementación deliberadamente insegura, usada como línea base para ver qué detectan las herramientas del pipeline cuando no hay protecciones.

Ambas exponen los mismos endpoints (login, ping, descarga de archivos, perfil, búsqueda), lo que permite comparar directamente los reportes de Bandit, Safety, Gitleaks, Trivy y ZAP entre una y otra.

## Descripción

Ambas versiones son un pequeño panel de administración web con las mismas rutas:

| Ruta | Método | Descripción |
|---|---|---|
| `/` | GET | Página principal |
| `/login` | GET/POST | Autenticación de usuario (bcrypt + SQLite parametrizado) |
| `/dashboard` | GET | Panel privado, requiere sesión activa |
| `/logout` | GET | Cierra la sesión |
| `/ping` | GET/POST | Ejecuta `ping` a un host indicado |
| `/download` | GET/POST | Lectura de archivos dentro de una carpeta controlada (protegido contra path traversal) |
| `/profile` | GET/POST | Genera un hash bcrypt a partir de una contraseña |
| `/search` | GET | Búsqueda simple |

## Stack

- **Backend:** Python 3.11 + Flask 3.x
- **Formularios:** Flask-WTF (protección CSRF)
- **Auth:** bcrypt + SQLite
- **Contenedor:** Docker (build multi-stage)

## Estructura del proyecto

```
.
├── app-segura/
│   ├── app.py               # Lógica de la aplicación Flask
│   ├── requirements.txt     # Dependencias Python
│   ├── Dockerfile
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── ping.html
│   │   ├── download.html
│   │   ├── profile.html
│   │   └── search.html
│   └── users.db              # Base de datos SQLite (usuarios)
│
├── app-vulnerable/
│   ├── app.py                # Misma lógica, sin protecciones (a propósito)
│   ├── init_db.py            # Crea users.db con credenciales en texto plano
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── templates/            # Mismos templates que app-segura
│   └── users.db
│
└── .github/workflows/
    ├── devsecops-segura.yml
    └── devsecops-vulnerable.yml
```

## Ejecución local

### Versión segura

```bash
cd app-segura
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="cambia_esto"
python app.py
```

### Versión vulnerable

```bash
cd app-vulnerable
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python init_db.py   # crea users.db con el usuario admin/admin123
python app.py
```

Ambas quedan disponibles en `http://localhost:5000`.

**La versión vulnerable no debe exponerse en redes públicas ni desplegarse en ningún entorno real.** Existe únicamente para fines educativos y para comparar los reportes del pipeline.

### Con Docker

```bash
# Segura
docker build -t secure-app ./app-segura
docker run -p 5000:5000 secure-app

# Vulnerable
docker build -t vulnerable-app ./app-vulnerable
docker run -p 5000:5000 vulnerable-app
```

## Pipeline DevSecOps (GitHub Actions)

Hay **dos workflows independientes**, uno por versión de la app, con los mismos jobs pero apuntando a carpetas distintas:

| Workflow | Analiza |
|---|---|
| `devsecops-segura.yml` | `app-segura/` |
| `devsecops-vulnerable.yml` | `app-vulnerable/` |

Cada uno ejecuta un pipeline de seguridad en capas, con jobs independientes:

| Job | Herramienta | Qué analiza |
|---|---|---|
| `bandit` | [Bandit](https://bandit.readthedocs.io/) | Código Python en busca de patrones inseguros (SAST) |
| `safety` | [Safety](https://pyup.io/safety/) | Dependencias de `requirements.txt` con CVEs conocidos |
| `gitleaks` | [Gitleaks](https://github.com/gitleaks/gitleaks) | Secretos y credenciales expuestas en el repositorio |
| `trivy` | [Trivy](https://aquasecurity.github.io/trivy/) | Vulnerabilidades del sistema operativo y librerías dentro de la imagen Docker |
| `zap` | [OWASP ZAP](https://www.zaproxy.org/) (baseline scan) | Vulnerabilidades en tiempo de ejecución (headers, cookies, CSRF, CSP...) sobre la app ya desplegada en un contenedor |

Cada job sube su reporte como **artifact** descargable desde la pestaña *Actions* de GitHub.

### Ejecutar el pipeline

Ambos workflows se disparan manualmente:

```
Actions → Pipeline DevSecOps (segura o vulnerable) → Run workflow
```

## Vulnerabilidades intencionales en `app-vulnerable`

Esta versión existe para que el pipeline tenga algo real que detectar, y para poder comparar el "antes y después" de aplicar buenas prácticas. Resumen de lo que cada herramienta debería encontrar aquí:

| Endpoint / archivo | Vulnerabilidad | Detectada por |
|---|---|---|
| `/login` | **SQL Injection**: la consulta se arma concatenando strings (`"... WHERE username='"+username+"'..."`) en vez de usar parámetros | Bandit (`B608`), ZAP |
| `/login` | Contraseña comparada en texto plano (sin hash) contra la base de datos | Bandit, revisión manual |
| `/ping` | **Command Injection**: `subprocess.check_output(..., shell=True)` concatenando el input del usuario directamente en el comando de shell | Bandit (`B602`/`B605`) |
| `/download` | **Path Traversal**: concatena `filename` directamente (`"uploads/" + filename`) sin validar ni resolver la ruta, permite `../../` para leer archivos fuera del directorio | Revisión manual / ZAP |
| `/profile` | Hash de contraseña con **MD5** (`hashlib.md5`), algoritmo criptográficamente roto para este uso | Bandit (`B303`) |
| Todo el formulario de login | **Ausencia de protección CSRF** (no usa Flask-WTF ni tokens) | ZAP |
| `app.secret_key = "supersecretkey"` | **Clave secreta hardcodeada** en el código fuente | Bandit (`B105`), Gitleaks |
| `API_KEY = "sk-1234567890abcdef"` | **Secreto/API key hardcodeada** en el código fuente | Gitleaks |
| `DB_PASSWORD = "admin123"` | **Credencial hardcodeada** en el código fuente | Bandit, Gitleaks |
| `response.set_cookie("sessionid", "123456")` | Cookie de sesión sin `HttpOnly`, `Secure` ni `SameSite`, y con valor fijo/predecible | ZAP |
| `init_db.py` | Usuario `admin` creado con contraseña en texto plano (`admin123`), sin hash | Revisión manual |
| `app.run(..., debug=True)` | **Modo debug activo**, expone el debugger interactivo de Werkzeug (ejecución remota de código si es alcanzable) | Bandit (`B201`) |
| `requirements.txt` (`Flask==2.2.5`) | Versión de Flask con CVEs conocidos ya parcheados en versiones posteriores | Safety |
| Imagen Docker (sin multi-stage, sin `apt upgrade`) | Base sin actualizar, arrastra `pip`/`setuptools` innecesarios en la imagen final | Trivy |

### Comparación rápida con `app-segura`

| Aspecto | `app-vulnerable` | `app-segura` |
|---|---|---|
| SQL | Concatenación de strings | Consultas parametrizadas (`?`) |
| Contraseñas | Texto plano / MD5 | `bcrypt` |
| `/ping` | `shell=True` con input directo | `subprocess.run([...])` sin shell |
| `/download` | Sin validar ruta | `os.path.abspath` + verificación de directorio base |
| CSRF | Ausente | `Flask-WTF` + `CSRFProtect` global |
| Secretos | Hardcodeados en el código | Variables de entorno (`os.getenv`) |
| Cookies | Sin flags de seguridad | `HttpOnly`, `SameSite`, `Secure` |
| Servidor | `debug=True`, dev server | Gunicorn, `debug=False` |
| Imagen Docker | Single-stage, sin actualizar | Multi-stage, `apt upgrade`, sin `pip` en runtime |

## Medidas de seguridad implementadas (en `app-segura`)

- **SQL Injection:** consultas parametrizadas (`?`) en vez de concatenación de strings.
- **Path Traversal:** validación de que la ruta resuelta (`os.path.abspath`) permanece dentro del directorio base permitido.
- **Contraseñas:** hash con `bcrypt`, nunca en texto plano.
- **CSRF:** `Flask-WTF` con `CSRFProtect` global, token en todos los formularios con estado.
- **Cookies:** `HttpOnly`, `SameSite=Lax`, `Secure` en producción.
- **Headers de seguridad:** CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-*-Policy`.
- **Imagen Docker:** build multi-stage (dependencias de compilación no viajan a la imagen final), `apt-get upgrade` para parchear el SO base, sin `pip`/`setuptools`/`wheel` en la imagen de producción.
- **Servidor:** Gunicorn en producción (no el servidor de desarrollo de Flask), con el header `Server` ofuscado.

## Notas sobre los reportes de seguridad

- **Trivy** puede seguir mostrando algunos hallazgos `UNFIXED` (sin parche publicado por Debian todavía). El workflow filtra por severidad (`CRITICAL,HIGH,MEDIUM`) e ignora los que no tienen parche disponible (`ignore-unfixed: true`), para centrar el reporte en lo accionable.
- **ZAP** ejecuta un *baseline scan* (pasivo, no exploit activo), por lo que sus hallazgos suelen ser de *hardening* (cabeceras, cookies, SRI) más que vulnerabilidades críticas explotables.

Proyecto con fines educativos / práctica de DevSecOps.
