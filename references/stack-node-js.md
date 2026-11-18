# Stack guide: Node.js, Next.js, NestJS, and JavaScript/TypeScript frontends

## Contents
- Quick triage greps
- Node/Express/NestJS backend
- Next.js, Nuxt and server-rendered frameworks
- React, Vue, Svelte and browser code
- npm ecosystem hygiene

## Quick triage greps (leads only)
```
grep -rnE "dangerouslySetInnerHTML|\.innerHTML\s*=|v-html|\{@html" src
grep -rnE "\beval\(|new Function\(|child_process|\bexec(Sync)?\(" .
grep -rnE "(localStorage|sessionStorage)\.(set|get)Item" src
grep -rnE "(REACT_APP|NEXT_PUBLIC|VITE|EXPO_PUBLIC|NUXT_PUBLIC)_[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD)" .
grep -rnE "jwt\.(decode|sign|verify)|algorithms|\bcors\(|origin:\s*['\"]\*" server src
grep -rnE "req\.(body|query|params)" server | head -200      # trace each to a DB call
```

## Node/Express/NestJS backend
- **Authn/authz (2.x, 3.x).** Auth middleware applied by default, with an explicit public allowlist; every handler re-checks ownership (`findOne({ _id, userId })`), not just "authenticated". NestJS: `@UseGuards` globally (`APP_GUARD`) plus roles guard; DTOs with `class-validator` and `whitelist: true, forbidNonWhitelisted: true` in `ValidationPipe`.
- **Mass assignment (3.2).** `User.create(req.body)`, `Object.assign(doc, req.body)`, `{ ...req.body }` into models, `findByIdAndUpdate(id, req.body)`. Pick fields explicitly or validate with a schema (Zod/Joi) that strips unknown keys.
- **NoSQL/SQL injection (4.1).** Mongo: `find({ email: req.body.email, password: req.body.password })` accepts `{"$ne": ""}`; cast with schema validation or `String(...)`; `express-mongo-sanitize`; no `$where`. SQL: `db.query(\`... ${x}\`)` fails; use placeholders (`?`, `$1`) or an ORM with bindings; Prisma `$queryRawUnsafe` / Sequelize `literal` and `sequelize.query` with interpolation fail.
- **Prototype pollution (5.9).** Deep-merging untrusted JSON (`lodash.merge`, `defaultsDeep`, hand-rolled `merge`, `Object.assign` on nested input) can set `__proto__`/`constructor.prototype`; use `structuredClone`, schema validation, `Object.create(null)`, or updated libraries.
- **Command/code injection (5.7).** `child_process.exec` with interpolated strings; use `execFile`/`spawn` with argument arrays and `shell: false`. No `eval`, `vm` as a sandbox, or dynamic `require(userInput)`.
- **Path traversal (5.8).** `path.join(base, req.params.file)` does not stop `../`; resolve and check the result starts with `base`; `express.static` only on a dedicated public folder, with `dotfiles: 'deny'`.
- **JWT (2.5).** `jwt.verify` (not `decode`) with an explicit `algorithms: ['HS256'|'RS256']` allowlist, strong secret from env, `exp`, `iss`, `aud`; separate access/refresh secrets; `express-jwt` `credentialsRequired` left true.
- **Cookies/sessions (2.5, 6.5).** `express-session`: `secure`, `httpOnly`, `sameSite`, non-default cookie name, persistent store (not MemoryStore) in production; `trust proxy` set correctly so `req.ip` and `secure` cookies work behind a proxy (also needed for rate-limit accuracy, 6.1).
- **Hardening (11.1, 6.x).** `helmet()` (report-only for CSP changes), `express-rate-limit` with a shared store (Redis), `cors` with an exact origin list, `app.disable('x-powered-by')`, body size limits (`express.json({ limit })`), request timeouts, centralised error handler that hides stack traces in production, `NODE_ENV=production`.
- **SSRF (5.4).** `axios/fetch/got(userUrl)`: validate and resolve host, block private ranges, disable or re-validate redirects. `rejectUnauthorized: false` / `NODE_TLS_REJECT_UNAUTHORIZED=0` fail 11.6.
- **Randomness (2.3).** `crypto.randomBytes`/`crypto.randomUUID`, never `Math.random()` for tokens, OTPs or IDs.
- **Uploads (5.3).** `multer` with `limits`, `fileFilter`, random filenames and a private destination; `formidable`/`busboy` size caps.
- **WebSockets/GraphQL (3.7, 6.7).** Authenticate the socket on connect and authorise every event/room join; GraphQL resolvers enforce object-level auth, depth/complexity limits, introspection off in production.
- **Serverless/edge.** Env vars per environment; functions don't log secrets; each function authenticates (no reliance on "unguessable URL"); CORS and rate limits at the function level.

## Next.js, Nuxt and server-rendered frameworks
- **Middleware is not the only gate (3.8).** Auth enforced only in `middleware.ts` can be bypassed (a 2025 Next.js middleware bypass was published). Every route handler, server action and server component fetching private data must call the session check itself and scope queries by user.
- **Server actions and route handlers (2.1, 5.1).** Server actions are public HTTP endpoints: validate input with a schema, check auth and ownership inside the action, never trust hidden form fields (ids, prices, roles).
- **Env leakage (1.1).** `NEXT_PUBLIC_*`, `VITE_*`, `NUXT_PUBLIC_*` ship to the browser. Server secrets must not be imported in client components. Check `next.config` `env:` entries. Don't pass whole DB rows (with password hashes or internal fields) as props to client components or `getServerSideProps`: they land in the HTML (6.4).
- **API routes (6.x).** `pages/api` and `app/api` handlers: method checks, auth, rate limits, CORS, webhook signature verification on raw body (disable body parser where required).
- **Images/redirects (5.4, 5.5).** `images.remotePatterns` restricted to your hosts (SSRF/abuse); `redirect()` targets validated.
- **Caching (3.1).** Authenticated responses aren't cached publicly (`Cache-Control: private/no-store`), and ISR/static caching never includes user-specific data.
- **Deploy (11.x).** Source maps decision (`productionBrowserSourceMaps`), `poweredByHeader: false`, preview deployments aren't public with production data, `X-Frame-Options`/CSP via `headers()` (report-only first).

## React, Vue, Svelte and browser code
- **XSS (5.2).** Avoid `dangerouslySetInnerHTML`/`v-html`/`{@html}`; if needed, sanitise with DOMPurify first. `href`/`src` from user input must block `javascript:` URLs. `target="_blank"` links use `rel="noopener noreferrer"`.
- **Secrets (1.1).** Nothing secret in the bundle; built `dist/` and source maps scanned with `quick_scan.py --include-build`. Third-party API keys that must be public are restricted by domain.
- **Auth state (2.1, 2.6).** Route guards are UX only. Tokens in `localStorage` are report-only (2.6). Don't store passwords, card data or PII in browser storage.
- **postMessage and window.open (5.5).** Check `event.origin` on `message` handlers; validate redirect targets.
- **Third-party scripts (10.4).** Tag managers, chat widgets and analytics on login/payment pages are a skimming risk; prefer SRI and minimal scripts.

## npm ecosystem hygiene (10.x)
Commit the lockfile, run `npm audit` (never `--force`), check `postinstall` scripts of unfamiliar packages, verify package names are real (10.5), prefer `npm ci` in CI, scope registry tokens, use 2FA for publishing, and watch for packages that were recently transferred or have a single anonymous maintainer.
