# Areas 1-3: Secrets, Authentication and sessions, Access control

## Contents
- Area 1: Secrets and API keys (5 checks)
- Area 2: Authentication and sessions (9 checks)
- Area 3: Authorization and access control (8 checks)

Stack-specific red flags for these checks are in the `stack-*.md` files.

---

## Area 1: Secrets and API keys
A leaked key is a blank cheque. Bots scan public repositories, app bundles and web pages for keys within minutes.

**1.1 No secret keys in client-shipped code.** Anything shipped to users (browser JS, built bundles, mobile app binaries, source maps) can be extracted. Search for cloud keys (`AKIA...`), payment secret keys (Stripe `sk_live_`, `rk_live_`), AI provider keys (`sk-`, `sk-ant-`, Gemini, Emergent `sk-emergent-`), database URLs with passwords, JWT/signing secrets, Supabase `service_role`, private keys, webhook secrets. Check env variables with public prefixes (`REACT_APP_`, `NEXT_PUBLIC_`, `EXPO_PUBLIC_`, `VITE_`, `NUXT_PUBLIC_`): they ship to every visitor. Pass: only publishable keys are client-side. Scan built output too (`quick_scan.py --include-build`).

**1.2 No secrets committed to code or history.** `.env` and key files are git-ignored. No secrets in config, Dockerfiles, CI files, notebooks, Postman exports or docs. If a secret was ever committed (check history with `git log -p -S` on a masked prefix, or a tool like gitleaks/trufflehog if installed), deleting it isn't enough: it must be revoked and replaced.

**1.3 Secrets are stored properly.** Secrets come from the platform's secret manager or environment variables, never hardcoded. Dev, staging and production use different secrets. `.env.example` has placeholders only.

**1.4 No secrets in logs, errors or analytics.** Keys, tokens, passwords, full card numbers and ID numbers are never logged, returned in error messages, put in URLs/query strings, or sent to analytics, crash reporters or session-replay tools.

**1.5 Keys are least-privilege and replaceable.** Each key has the minimum scope (read-only where possible, restricted by domain/IP/app ID for browser and mobile keys), a spending cap or alert where the provider offers one, and the owner knows how to rotate it. Mark CAN'T VERIFY when it depends on the provider dashboard.

---

## Area 2: Authentication and sessions
Every other protection assumes we know who the user is.

**2.1 Every private route verifies the session on the server.** Each route, controller, server action, GraphQL resolver and background endpoint that touches private data checks the session or token on the server. Hiding a button or a client-side route guard is not protection. List every private route in AUDIT.md.

**2.2 Passwords are handled safely.** Prefer a managed identity provider. If the app stores passwords itself: slow hashes only (argon2id, bcrypt, scrypt; PHP `password_hash`, Django hashers, Laravel `Hash`), never plain text, MD5/SHA-1/SHA-256, or reversible encryption. No admin or test account created at startup or in a seed/migration with a known or default password. If one exists in production code paths, mark **Critical**.

**2.3 Password reset and verification are safe.** Reset and verification tokens come from a cryptographically secure generator (not `rand`, `Math.random`, `uniqid`, timestamps), are long, single-use, short-lived and stored hashed; responses and timing don't reveal whether an email is registered; the reset link isn't built from the Host header; changing the email requires re-authentication.

**2.4 Login is protected from guessing.** Rate limits or lockouts per account and per IP on login, signup, OTP, password reset and MFA verification (see 6.1). OTPs are short-lived, limited in attempts, and not returned in the API response.

**2.5 Tokens and sessions are verified and expire.** Tokens are verified with their signature (never just decoded), the `none` algorithm and algorithm confusion are rejected, no default/example secret is used, issuer and audience are checked, sessions expire and logout ends them server-side. Session ID is regenerated on login (session fixation). Cookies are `HttpOnly`, `Secure` and `SameSite`. Compare secrets in constant time and with strict equality (PHP `hash_equals`, not `==`).

**2.6 Tokens aren't kept in web storage. REPORT ONLY.** If the login method supports secure cookies, tokens shouldn't sit in `localStorage` or `sessionStorage`, where any injected script can read them. Flag as Medium. Never move token storage as a fix; it changes the whole auth flow and needs the owner's design decision.

**2.7 Social login and redirects are locked down.** OAuth/OIDC redirect URLs are an exact allowlist; `state` (and PKCE for public clients) is used; accounts are linked only on a verified email; there's no open redirect after login (see 5.5). Allowlists must include production and custom domains.

**2.8 Strong authentication where it matters.** Admin accounts and high-risk actions (change email/password, withdraw or transfer money, create API keys, export data) require MFA or re-authentication (step-up). MFA recovery can't be bypassed by support flows or "forgot password".

**2.9 Sessions are revoked when they should be.** Password change, MFA change, role downgrade and account deletion invalidate existing sessions and refresh tokens; refresh tokens rotate; stolen-token reuse is detected where feasible.

---

## Area 3: Authorization and access control
Broken access control is the #1 risk in the OWASP Top 10. Classic version: logged in as Rahul, change an ID in the URL, see Priya's data (IDOR).

**3.1 Every record checks ownership.** Every read, update and delete filters by the logged-in user (or their team/tenant), e.g. `WHERE id = ? AND user_id = ?`, `{"_id": id, "user_id": uid}`, a Laravel policy, a Django queryset scoped to `request.user`. Not just by ID. List every table/collection and route checked in AUDIT.md. Include file downloads, exports, reports, search, bulk endpoints and background jobs.

**3.2 Users can't promote themselves (mass assignment).** Create/update endpoints, including signup and profile update, accept only an explicit allowlist of fields. `role`, `is_admin`, `plan`, `credits`, `balance`, `verified`, `tenant_id`, `owner_id`, `subscription_status` are never settable from the request. The request body is never written straight to the database (`Model::create($request->all())`, `Object.assign(doc, req.body)`, `fields = '__all__'`, empty `$guarded`).

**3.3 Admin areas are protected on the server.** Admin pages and APIs check an admin role on the server for every request. A secret or obscure URL is not protection. Always run, even for apps without user login.

**3.4 Paid features and limits are enforced on the server.** Plan limits, credits, quotas and premium features are checked server-side, not only hidden in the UI.

**3.5 Teams and tenants stay separate.** If the app has teams, organisations or workspaces, every query is scoped to the caller's own tenant (see area 9 for the full SaaS checks).

**3.6 Debug and test routes are off in production.** No public debug pages, test endpoints, seed or reset routes, "temporary" admin routes, profiler/telescope dashboards, or `phpinfo` pages. Always run, even for apps without login.

**3.7 Function-level authorization per action.** Authorization is checked per verb and per role, not just "is logged in": a viewer who can GET an item can't PUT/DELETE it; a normal user can't call an admin-only API by guessing its path; GraphQL fields and nested objects enforce the same rules as REST.

**3.8 Deny by default.** New routes are protected unless explicitly public (global auth middleware or guard with an explicit public allowlist). Authorization isn't enforced only in edge middleware or a gateway that can be bypassed: sensitive route handlers and server actions re-check the session themselves (middleware-only auth has been bypassed in popular frameworks). Internal and "service-to-service" endpoints are not reachable from the internet unauthenticated.
