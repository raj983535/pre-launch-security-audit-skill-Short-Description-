# Stack guide: Python (Django, DRF, Flask, FastAPI)

## Contents
- Quick triage greps
- Language-level pitfalls
- Django and DRF
- Flask
- FastAPI and Starlette

## Quick triage greps (leads only)
```
grep -rnE "\b(eval|exec)\(|pickle\.loads?|marshal\.loads|yaml\.load\(|os\.system|subprocess\..*shell=True" .
grep -rnE "\.(raw|extra)\(|execute\(f['\"]|execute\(.*(%|\+|format)" .
grep -rnE "DEBUG\s*=\s*True|app\.run\(.*debug|ALLOWED_HOSTS\s*=\s*\[.\*|allow_origins=\[.\*|CORS_ALLOW_ALL" .
grep -rnE "csrf_exempt|mark_safe|\|safe|render_template_string|AllowAny|fields\s*=\s*.__all__" .
grep -rnE "verify=False|hashlib\.(md5|sha1)|random\.(randint|choice|random)\(" .
```

## Language-level pitfalls
- **Injection (4.1, 5.7).** Parameterised queries only: `cursor.execute("... WHERE id = %s", [id])`; f-strings, `%` formatting and `+` in SQL fail. ORM escape hatches (`.raw()`, `.extra()`, `RawSQL`, SQLAlchemy `text(f"...")`) must use bound parameters; dynamic column/order names use an allowlist.
- **Deserialization (5.9).** `pickle`, `marshal`, `shelve`, `yaml.load` (use `yaml.safe_load`), `jsonpickle`, `dill` on untrusted data is remote code execution. Don't unpickle cache/session/queue data that users can influence; sign or use JSON.
- **Shell (5.7).** `subprocess.run([...], shell=False)` with argument lists; no `os.system`, `shell=True`, `eval`, `exec`, `input()`-style dynamic evaluation of user data.
- **Templates (5.2, 5.10).** Jinja2 autoescape on; never `render_template_string` / `Template(user_input)` (server-side template injection); Django `mark_safe`/`|safe` only on trusted, sanitised HTML (use `bleach`/`nh3`).
- **Files (5.3, 5.8).** `werkzeug.utils.secure_filename` plus random names; `os.path.realpath` containment checks; `tarfile`/`zipfile` extraction guarded against traversal (zip-slip); `Pillow` re-encode images.
- **TLS and requests (5.4, 11.6).** `requests.get(user_url)` needs SSRF protection (resolve and block private ranges, `allow_redirects=False` or re-validate), timeouts, size limits; `verify=False` fails.
- **Randomness and hashing (2.2, 2.3).** `secrets.token_urlsafe()`/`secrets.compare_digest` for tokens and comparisons; `random` module is not for security; passwords via argon2/bcrypt (`passlib`, `argon2-cffi`, Django hashers), never `hashlib.md5/sha1/sha256` alone.
- **JWT (2.5).** `jwt.decode(token, key, algorithms=[...])` with explicit algorithms and verification on; never `verify_signature: False`.
- **Dependencies (10.x).** Pin in `requirements.txt`/lockfile, `pip-audit`, check for typosquatted packages (10.5).

## Django and DRF
- `DEBUG=False`, a unique secret `SECRET_KEY` from env (a leaked key allows forging sessions/signed data and, with pickle serializers, code execution), `ALLOWED_HOSTS` explicit, `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS`, `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS`; run `python manage.py check --deploy` and report its warnings (11.1, 11.2).
- Admin: `/admin/` not at the default path if feasible, MFA for staff, limited staff accounts, not exposed publicly without need (11.3).
- Object-level authorisation (3.1, 3.7): DRF `permission_classes` set globally to `IsAuthenticated` (not `AllowAny`) with per-view overrides; `get_queryset()` filters by `request.user`/tenant; `has_object_permission` where `get_object()` is used; check `ModelViewSet` exposes only intended verbs.
- Serializers (3.2, 6.4): explicit `fields` (never `'__all__'` for user-writable models); `read_only_fields` for `role`, `is_staff`, `owner`, `balance`; separate serializers for create/update and for public/private views.
- CSRF (6.5): `@csrf_exempt` only for signature-verified webhooks; SessionAuthentication keeps CSRF enforcement.
- Rate limiting (6.1): DRF throttling with a shared cache backend (Redis), or `django-ratelimit`; login throttled per account and IP.
- Uploads (5.3): `FileField` validators, `MEDIA_ROOT` outside static serving of executables, private storage for sensitive files, signed URLs.
- Migrations/seeds (2.2): no default superuser with a known password in data migrations or fixtures.

## Flask
- `app.run(debug=True)` / `FLASK_DEBUG=1` exposes the Werkzeug debugger, which can lead to code execution: never in production; run behind gunicorn/uwsgi (11.2).
- `SECRET_KEY` strong and from env; `SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE` set; consider server-side sessions; `Flask-WTF` CSRFProtect enabled (6.5); `Flask-Limiter` with Redis (6.1); `Flask-CORS` with explicit origins (6.2); `Flask-Talisman` for headers (report-only first).
- Authorisation is manual: every route has an auth decorator, and every DB lookup scopes by user; list every `@app.route` in AUDIT.md (2.1, 3.1).
- Avoid `render_template_string` with user input; `|safe` reviewed (5.2).

## FastAPI and Starlette
- Pydantic models for every request body, path and query parameter (5.1); `response_model` on every route to avoid leaking fields (6.4); separate "create"/"update"/"read" models excluding `role`, `is_admin`, `balance`, `owner_id` (3.2).
- Auth via `Depends(get_current_user)` on every private route; dependency applied at the router level with an explicit public allowlist (3.8); verify JWT signature and claims (2.5); ownership filters in every query (3.1).
- `docs_url=None, redoc_url=None, openapi_url=None` in production or protect them (11.3).
- `CORSMiddleware`: never `allow_origins=["*"]` with `allow_credentials=True` (6.2).
- Rate limiting via `slowapi` or gateway with a shared store (6.1); request size limits at the proxy; background tasks and Celery jobs don't run unbounded paid calls (12.2).
- Async pitfalls: blocking calls in async handlers cause DoS under load (6.7); per-request DB sessions closed; no global mutable state holding user data between requests (3.1).
- Mongo (Motor/Beanie): validate types so operators can't be injected (4.1).
