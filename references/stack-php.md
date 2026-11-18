# Stack guide: PHP (plain PHP, Laravel, Symfony, WordPress, CodeIgniter, legacy)

Read this alongside the numbered checks. It tells you what to grep for and which check each red flag belongs to. PHP's history of weak defaults, loose typing and a huge plugin ecosystem make it the most common source of real-world web compromises, so treat every item here seriously.

## Contents
- Quick triage greps
- Language-level pitfalls
- Web root, config and deployment
- Laravel
- Symfony
- WordPress (plugins, themes, custom code)
- CodeIgniter and legacy code

---

## Quick triage greps (leads only; confirm in code)
```
grep -rnE "\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)" --include=*.php .     # every input source
grep -rnE "\b(eval|assert|create_function|system|exec|shell_exec|passthru|popen|proc_open)\s*\(" --include=*.php .
grep -rnE "unserialize\s*\(|\b(include|require)(_once)?\s*\(?\s*\$" --include=*.php .
grep -rnE "mysql_(query|connect)|mysqli?_query\s*\(.*\\$|->query\s*\(.*\\." --include=*.php .
grep -rnE "\b(md5|sha1|crypt)\s*\(" --include=*.php .                       # password hashing?
grep -rnE "\b(rand|mt_rand|uniqid|srand|shuffle)\s*\(" --include=*.php .    # tokens/OTPs?
grep -rnE "move_uploaded_file|file_get_contents\s*\(\s*\$|curl_setopt.*(VERIFYPEER|VERIFYHOST)" --include=*.php .
```
`scripts/quick_scan.py` runs these and more.

## Language-level pitfalls
- **SQL injection (4.1).** Every query uses PDO/mysqli prepared statements with bound parameters. Disable emulated prepares for PDO MySQL (`PDO::ATTR_EMULATE_PREPARES => false`) and set the charset in the DSN. Dynamic table/column/ORDER BY names come from an allowlist. `mysql_*` functions mean the code is from PHP 5 era: rewrite, not patch. `real_escape_string` alone is not a fix.
- **Type juggling (2.1, 2.5).** `==` between strings can match unexpectedly (`"0e123" == "0e456"`, `"abc" == 0` on old versions); `in_array`, `array_search`, `switch` and `strcmp` use loose comparison. For hashes, tokens, passwords and role checks use `===`, `hash_equals()`, `password_verify()`, and `in_array(..., true)`. Flag `md5($x) == ...` style checks.
- **Password hashing (2.2).** `password_hash($p, PASSWORD_DEFAULT|ARGON2ID)` / `password_verify` / `password_needs_rehash`. MD5, SHA-1, SHA-256 or `crypt` with a static salt are failures.
- **Randomness (2.3).** Tokens, reset links, OTPs and API keys use `random_bytes()`/`random_int()`, not `rand`, `mt_rand`, `uniqid`, `time()`, or `md5(rand())`.
- **Sessions (2.5).** `session_regenerate_id(true)` on login and privilege change; `session.cookie_httponly=1`, `session.cookie_secure=1`, `session.cookie_samesite=Lax|Strict`, `session.use_strict_mode=1`, `session.use_only_cookies=1`. Never put the session ID in URLs.
- **Remote code execution sinks (5.7).** `eval`, `assert` with strings, `create_function`, `preg_replace` with the `/e` modifier (old code), `system/exec/shell_exec/passthru/popen/proc_open` and backticks, `call_user_func`/variable functions with user-controlled names, `include/require` of user-influenced paths (5.8). If a shell is unavoidable use `escapeshellarg`/array form and allowlists.
- **File inclusion and traversal (5.8).** `include $_GET['page']` is Critical. Map user choices to an allowlist of files. Set `allow_url_include=Off`, `allow_url_fopen=Off` where possible. Filesystem functions accept `phar://`, `php://`, `data://`: don't pass user paths to `file_exists`, `file_get_contents`, `fopen`, `copy`, `getimagesize` etc. without validation (phar deserialization).
- **Deserialization (5.9).** `unserialize()` on anything a user can influence (cookies, form fields, uploaded files, cached data from shared stores) enables object injection; use `json_decode`, or `unserialize($s, ['allowed_classes' => false])` at minimum.
- **Variable overwrite (3.2).** `extract($_POST)`, `parse_str($s)` without a result array, `$$var` variable-variables, and `register_globals`-style code let users overwrite internal variables (e.g. `$is_admin`). Remove.
- **XSS (5.2).** Every output of user data goes through `htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')` or the template engine's auto-escape. Echoing `$_GET`, `$_SERVER['PHP_SELF']`, `$_SERVER['REQUEST_URI']` raw is XSS.
- **Uploads (5.3).** Check real MIME (`finfo`) and extension allowlist; random filenames; store outside the document root or in a folder where the web server will not execute PHP (`php_flag engine off`, `RemoveHandler`, Nginx `location ~ \.php$ { deny all; }` for uploads); never trust `$_FILES['x']['type']` or `name`; double extensions (`shell.php.jpg`) and `.phtml/.phar/.php5` must be blocked; re-encode images.
- **Header, redirect and mail injection (5.5, 5.10).** Strip CR/LF from anything placed in `header()` or `mail()` headers; allowlist redirect targets.
- **SSRF (5.4).** `file_get_contents($url)`, `curl` with user URLs, `SoapClient`, `simplexml_load_file` with URLs; validate scheme/host/IP and set `CURLOPT_FOLLOWLOCATION=false` or re-validate redirects. `CURLOPT_SSL_VERIFYPEER=false` or `VERIFYHOST=0` fails 11.6.
- **XXE (5.9).** On PHP < 8, call `libxml_disable_entity_loader(true)`; never use `LIBXML_NOENT`/`LIBXML_DTDLOAD` on user XML.
- **Error handling (5.6, 11.2).** `display_errors=Off`, `log_errors=On`, `error_reporting` set, `expose_php=Off`. No `phpinfo()` file left behind.
- **Supported PHP version (10.1).** Flag end-of-life PHP versions; run `composer audit`.

## Web root, config and deployment (11.3, 11.4, 11.8)
- Only the public folder (`public/`, `web/`, `public_html` subfolder) is the document root. If `vendor/`, `.env`, `composer.json/lock`, `storage/`, `app/`, `config/`, `database/` or `.git` are reachable by URL, that's a Critical finding.
- Disable PHP execution in upload/cache/storage dirs. Deny dotfiles (`.env`, `.git`, `.htaccess` readable) and backup extensions in server config.
- Remove `phpinfo.php`, `info.php`, `test.php`, `adminer.php`, `phpmyadmin`, `install/`, `setup/`, `.sql` dumps, `.zip` backups from deployed folders.
- File permissions: code not writable by the web user; no `777`.
- Cron/queue workers and CLI scripts under the web root must refuse web access.

## Laravel
- `APP_DEBUG=false` and `APP_ENV=production` in production (debug pages have historically enabled remote code execution via Ignition). `APP_KEY` is secret, unique per environment, and was never committed: a leaked `APP_KEY` can allow forging encrypted cookies and, in some versions, code execution via deserialization. If leaked, rotate (invalidates sessions).
- Mass assignment (3.2): every model has `$fillable` (preferred) and never `$guarded = []`; avoid `Model::create($request->all())`; use `$request->validated()` from Form Requests; `forceFill`, `unguard()` and `Model::unguarded()` need review.
- Authorisation (3.1, 3.7, 3.8): Policies/Gates on every controller action (`$this->authorize`, `can:` middleware, `Gate::authorize`); route model binding scoped to the owner (`->scopeBindings()` or `where('user_id', auth()->id())`); `php artisan route:list` to find unprotected routes; `Route::resource` exposes all verbs.
- SQL (4.1): `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`, `DB::statement`, `DB::unprepared` with variables must use bindings (`?`); `orderBy($request->sort)` needs an allowlist.
- XSS (5.2): `{{ }}` is escaped; `{!! !!}` is not. Check every use.
- CSRF (6.5): `@csrf` in web forms; `VerifyCsrfToken::$except` should be tiny (webhooks only, with signature checks).
- Uploads (5.3): validate with `mimes`/`image`/`max` rules *and* store with `store()` to a private disk; `php artisan storage:link` makes `storage/app/public` web-readable, so keep private files on the `local` disk.
- Debug tooling (3.6, 11.3): Telescope, Horizon, Debugbar, Ignition routes, `/_debugbar`, `/telescope`, `/horizon`: disabled or gated in production (`Gate::define('viewTelescope')`).
- Rate limiting (6.1): `throttle` middleware on login, register, password reset, OTP, API; `RateLimiter::for()`. Behind a proxy, configure `TrustProxies` correctly so IPs are real.
- Auth (2.x): `Hash::make`, Sanctum/Passport token abilities, `password.confirm` middleware for sensitive actions, email verification (`verified` middleware), session `secure`/`http_only`/`same_site` in `config/session.php`, `SESSION_DRIVER` not `file` on multi-server.
- Mail/queue/URL (5.10): `URL::forceScheme('https')`, trusted hosts (`TrustHosts`) so reset links aren't built from a forged Host header.
- `.env` in `.gitignore`; `config:cache` in production; `composer install --no-dev`.

## Symfony
`APP_ENV=prod`, `APP_DEBUG=0`; profiler/web-debug-toolbar (`/_profiler`, `/_wdt`) not routed in prod; `APP_SECRET` secret; `security.yaml` firewalls cover every route and `access_control` is ordered correctly (first match wins); voters/`#[IsGranted]` for object-level ownership (3.1); Doctrine DQL/`createQuery` with parameters, never concatenation; Twig `|raw` reviewed; CSRF tokens on forms; `framework.trusted_proxies` configured; secrets in the Symfony secrets vault, not committed.

## WordPress (plugins, themes, custom code)
- Most WordPress compromises come from **outdated or abandoned plugins/themes** and "nulled" (pirated) premium plugins (10.1, 10.3). List every plugin/theme with version; flag anything not updated in ~2 years or with known vulnerabilities; remove unused ones; core, plugins and themes auto-update where safe.
- Custom code: every state-changing action verifies a **nonce** (`check_admin_referer`, `wp_verify_nonce`) *and* a **capability** (`current_user_can('manage_options')`); `admin-ajax.php`/`wp_ajax_nopriv_*` and REST routes need `permission_callback` (never `__return_true` for private data) (2.1, 3.7).
- Data handling: `$wpdb->prepare()` for every query with variables (4.1); sanitise on input (`sanitize_text_field`, `absint`) and escape on output (`esc_html`, `esc_attr`, `esc_url`, `wp_kses_post`) (5.1, 5.2); `wp_handle_upload` with a mime allowlist (5.3).
- Config: strong DB prefix is optional; `wp-config.php` not world-readable or served, unique salts/keys, `define('DISALLOW_FILE_EDIT', true)`, `WP_DEBUG` false and `WP_DEBUG_DISPLAY` false, `xmlrpc.php` disabled unless needed, user enumeration (`/?author=1`, `/wp-json/wp/v2/users`) limited, default `admin` username removed, login rate-limited and MFA on admin accounts (2.4, 2.8), file permissions 644/755, uploads folder without PHP execution, backups not stored in `wp-content/`.

## CodeIgniter, CakePHP, Yii and legacy code
Turn on the framework's CSRF filter and global XSS output escaping (`esc()`/`h()`); use Query Builder/ORM binding, not raw `$db->query("... $x")`; `ENVIRONMENT` set to production; remove installer/welcome controllers; don't expose `system/`, `application/`, `writable/` folders in the web root. For legacy procedural PHP with no framework: treat every file in the web root as an entry point, list them all in AUDIT.md with whether they require login (2.1), and plan a migration rather than patching one flaw at a time.
