# Areas 4-6: Data layer, Input and output handling, API abuse protection

## Contents
- Area 4: Data layer and file storage (7 checks)
- Area 5: Input and output handling (10 checks)
- Area 6: API abuse protection (7 checks)

---

## Area 4: Data layer and file storage
Most leaks come from a missing rule, not a clever hack.

**4.1 Queries can't be hijacked (injection).** User input never reaches a query as code. SQL uses parameter binding / prepared statements everywhere (PHP PDO/mysqli prepared statements with bound params, not string concatenation or `mysql_*`; ORM raw escape hatches like `DB::raw`, `whereRaw`, `.raw()`, `.extra()`, `$queryRawUnsafe` always bound). NoSQL: a login sending `{"$ne": null}` must not match every user; validate types (strings stay strings), never pass request JSON as a filter, no `$where`/server-side JS. Check ORDER BY / column / table names built from input against an allowlist.

**4.2 Public IDs are unguessable.** IDs in URLs and API responses are random (UUIDv4/ULID) rather than sequential integers or Mongo ObjectIds. Severity **Low** if 3.1 passes, because ownership checks are the real protection.

**4.3 File storage is private by default.** User files are private, served through short-lived signed URLs or an authenticated download route, never from a guessable public path. Users can't overwrite each other's files. Cloud buckets aren't public-list/public-read unless they hold deliberately public assets only.

**4.4 The database isn't directly reachable or default-configured.** Connection strings are server-only; DB, Redis, Elasticsearch, Mongo and message-queue ports aren't open to the internet; no default or empty passwords; DB users have least privilege (the app user can't DROP or read other schemas); admin tools (phpMyAdmin, Adminer, Mongo Express, Redis Commander) aren't exposed. Mark CAN'T VERIFY when network rules live in a console you can't see.

**4.5 BaaS rules are tight (Supabase, Firebase, similar).** Supabase: RLS enabled on every exposed table, every policy ties rows to `auth.uid()` (no `using (true)`), only needed roles are granted (never fix error 42501 by granting everything to `anon`), `service_role` is server-only, views and `SECURITY DEFINER` functions don't bypass RLS, storage buckets have policies. Firebase: Firestore, Realtime Database and Storage rules aren't in test mode (`allow read, write: if true`) and check `request.auth.uid`. Mass exposures of Supabase databases with missing RLS have been documented; treat this as a top-priority check for AI-built apps.

**4.6 Sensitive data is minimised and protected.** Collect only what's needed. Passwords hashed (2.2). Highly sensitive fields (government IDs, bank details, health data, KYC documents, API tokens of the user's connected accounts) are encrypted at rest with keys held outside the database. TLS to the database where it crosses a network.

**4.7 Backups exist and are restorable.** Automated backups, stored separately from the live database, encrypted, access-controlled, with a restore that has actually been tested. Usually CAN'T VERIFY from code; put it in the human checklist.

---

## Area 5: Input and output handling
Anything a user types, uploads or links to can be a weapon if trusted blindly.

**5.1 All input is validated on the server.** Every endpoint validates type, length, range and allowed values (Pydantic, Zod/Joi, Laravel form requests, Django serializers, Bean Validation). Front-end validation alone doesn't count. Reject unknown fields where practical; cap request body size.

**5.2 No cross-site scripting (XSS).** User content is output-encoded for its context. No raw HTML insertion (`dangerouslySetInnerHTML`, `innerHTML`, `v-html`, Blade `{!! !!}`, Django `|safe`/`mark_safe`, PHP `echo $_GET[...]`). Markdown/rich text is sanitised with an allowlist sanitiser (DOMPurify, HTMLPurifier). Links with user-supplied `javascript:` URLs are blocked.

**5.3 File uploads are restricted.** Type and size limits on the server; real file type checked by content, not just extension or the client's MIME; files renamed to random names; stored outside the web root or on private object storage; never executed (a `.php`/`.jsp`/`.aspx` upload landing in a served folder is remote code execution); SVG and HTML uploads blocked or sanitised; images re-encoded when displayed to others; archive extraction guards against path traversal (zip-slip).

**5.4 No server-side request forgery (SSRF).** If the server fetches a user-provided URL (webhooks, link previews, image import, PDF/HTML-to-image, OAuth discovery), allow only `http(s)`, resolve the host and reject any address that isn't publicly routable (loopback, private ranges, link-local and cloud metadata addresses like 169.254.169.254), connect to the address you checked (defeat DNS rebinding), re-check after every redirect, and cap response size and time.

**5.5 No open redirects.** Any `?redirect=`, `?next=`, `returnUrl` parameter allows only the app's own relative paths or an allowlist of hosts.

**5.6 Errors fail safely.** Users see generic messages, never stack traces, SQL errors, framework debug pages or file paths. If a multi-step action fails halfway (payment taken but order not saved), the app rolls back or recovers; use transactions.

**5.7 No command or code injection.** User input never reaches `eval`, `exec`, `system`, `shell_exec`, `child_process.exec`, `subprocess(..., shell=True)`, `Runtime.exec`, backticks, `new Function`, dynamic `require/import`, or template/expression engines. If a shell is unavoidable: argument arrays, no shell, strict allowlists.

**5.8 No path traversal or file inclusion.** Filenames and paths from users are never joined into file paths without canonicalising and checking they stay inside the intended folder (`../`, absolute paths, null bytes, `php://`, `file://`, `phar://`). Never `include/require` a path built from input. Remote file inclusion (`allow_url_include`) is off.

**5.9 No unsafe deserialization or parser abuse.** Don't deserialize untrusted data with native object serializers (PHP `unserialize`, Python `pickle`/`yaml.load`/`marshal`, Java `ObjectInputStream`, .NET `BinaryFormatter`, Ruby `Marshal`/`YAML.load`, Node `node-serialize`); use JSON with schema validation. XML parsers disable external entities (XXE). Beware prototype pollution when merging user JSON into objects (Node).

**5.10 No template, header or email injection.** User input isn't rendered as a template (`render_template_string`, Twig/Blade/Jinja built from input); CR/LF is stripped from values placed in headers, redirects and email headers (`mail()` header injection); email "from/to" can't be set by users to relay spam.

---

## Area 6: API abuse protection
Bots don't need to hack you to hurt you. Spam, scraping, credential stuffing and free-tier abuse drain money and data.

**6.1 Rate limits that actually work.** Per-user and per-IP limits on login, signup, OTP, password reset, forms, search, AI calls, uploads and expensive endpoints. Limits use shared storage (database or Redis), not in-memory counters that reset on restart or differ between servers. Read the real client IP from the trusted proxy header, not the proxy's own IP; never trust the first `X-Forwarded-For` value, because the client controls it; use the address set by the platform's own proxy and, if you can't confirm how it sets it, mark the IP source **Suspected**. Limits on login and AI calls must also apply per account.

**6.2 CORS allows only your domains.** The real bug is accepting any origin while allowing credentials, or reflecting the `Origin` header back. Require an exact list of own origins (including the production and custom domains). `null` origin isn't allowed.

**6.3 Bot protection on public forms.** Signup, contact, waitlist and password-reset forms have a CAPTCHA or proof-of-work (e.g. Cloudflare Turnstile, hCaptcha) or equivalent throttling.

**6.4 APIs return only what's needed.** Responses use explicit response models/resources/serializers. They never include password hashes, tokens, internal fields, other users' emails or phone numbers; lists are paginated with a maximum page size; GraphQL introspection and verbose errors are off in production where not needed.

**6.5 CSRF protection.** If login uses cookies (or HTTP auth), every state-changing request is protected (`SameSite` cookies plus CSRF tokens or origin checks); GET requests never change state. Not needed for pure bearer-token APIs that don't use cookies.

**6.6 Incoming webhooks are verified.** Every Stripe, Razorpay, PayPal, GitHub, Twilio or other webhook verifies the provider's signature over the raw body, rejects failures, checks the timestamp to stop replays, and processes each event only once (idempotent by event ID).

**6.7 Expensive requests are bounded.** Pagination caps, maximum payload and upload sizes, query timeouts, GraphQL depth/complexity limits, regex inputs that can't cause catastrophic backtracking (ReDoS), and limits on bulk/export operations, so one request can't take the service down or run up the bill.
