# Areas 7-9: Payments and fintech, AI/LLM features, Multi-tenant SaaS

## Contents
- Area 7: Payments, money and fintech (12 checks)
- Area 8: AI and LLM features (6 checks)
- Area 9: Multi-tenant SaaS (7 checks)

---

## Area 7: Payments, money and fintech
Payment and ledger bugs turn directly into lost money, chargebacks, fraud and legal trouble. For fintech (wallets, lending, trading, transfers, neobanks) run ALL of 7.1-7.12; for a simple "buy a plan" checkout, 7.1-7.7 are the core.

**7.1 Prices are decided on the server.** The client sends only a plan/product ID and quantity. The server looks up the real price and never trusts an amount, currency, discount or user ID from the client.

**7.2 Access is granted only after verified payment.** Premium access or credited balance comes from a verified provider webhook, or a server-side check of the provider's payment signature, never from landing on a "success" page or a client callback. Also a **PASS**: the server asks the provider directly (e.g. Stripe session status) provided the session belongs to the logged-in user and is credited only once. Don't rewrite a working flow like this, but renewals and refunds (7.3) still need webhooks. Mobile in-app purchases are verified with Apple/Google on the server.

**7.3 The full payment lifecycle is handled.** Renewals, failed payments, refunds, chargebacks/disputes, cancellations and downgrades all update access and balances correctly.

**7.4 Test and live keys are separated.** Live secret keys exist only on the production server. Test mode can't be switched on in production by a request parameter.

**7.5 Credits, coupons and trials can't be farmed.** One trial per user (and per payment method/device where relevant), coupons validated server-side with usage limits, referral rewards limited, and balances changed in a single atomic update so two fast requests can't spend the same credits twice.

**7.6 Billing terms are visible.** Price, billing period, auto-renewal and how to cancel are shown next to the pay button; a working cancel option exists.

**7.7 Money maths is exact.** Amounts are stored as integers in minor units (paise/cents) or fixed-point decimals, never floats; currency is stored with every amount; rounding rules are explicit; negative, zero, huge and overflow values are rejected; currency conversion rates and fees are computed server-side.

**7.8 Idempotency and race conditions.** Money-moving endpoints accept an idempotency key and are safe to retry. Balance checks and debits happen inside one database transaction with row locks or atomic conditional updates (`UPDATE ... SET balance = balance - ? WHERE balance >= ?`), plus unique constraints, so concurrent requests can't double-spend, double-withdraw or redeem twice. Test: fire the same request twice in parallel in the dev environment.

**7.9 Ledger integrity.** Financial records are append-only (corrections are new entries, not edits/deletes); double-entry or equivalent so totals reconcile; every entry has actor, time, reason and reference; a reconciliation job compares internal records to the provider/bank; the application's DB user can't `UPDATE`/`DELETE` ledger rows if avoidable.

**7.10 Sensitive money actions have extra controls.** Withdrawals, transfers, payout-account changes and limit increases require step-up auth (2.8); new beneficiaries have a cooldown or confirmation; per-user and global velocity/amount limits exist; admin money operations need two people (maker-checker) and are audit-logged; unusual activity triggers alerts or holds.

**7.11 Card and bank data scope is minimal.** Card numbers (PAN), CVV and full bank credentials are never stored or logged by the app; card entry uses the provider's hosted fields/checkout/tokenisation so the app stays out of PCI scope; only provider tokens and last-4 are kept.

**7.12 KYC and identity documents are protected.** ID documents, selfies and verification results are stored encrypted in private storage, accessible only to authorised staff roles with access logging, retained no longer than the law and business need require, and deleted on request where allowed. Verification status can't be set by the user (3.2).

---

## Area 8: AI and LLM features
Based on the OWASP Top 10 for LLM Applications. AI calls cost real money and can be manipulated.

**8.1 AI usage has limits.** Per-user quotas, rate limits, maximum input size, maximum output tokens and timeouts exist in the app, not just at the provider. Without per-user limits one user can burn the owner's whole credit balance. At the provider, use a hard spending cap where one exists; otherwise prepaid credit with auto-recharge off.

**8.2 The AI can't be talked into misusing its powers.** Treat everything the model reads that the user didn't write (web pages, uploaded files, emails, tickets, other users' content, tool outputs) as untrusted: hidden instructions in it must not trigger actions or reveal data. Tools the model can call are limited, scoped to the current user's data and permissions, and require confirmation for anything destructive, costly or outward-facing (sending email, payments, deleting). The model never gets unrestricted database, shell or file-system access. Code execution by the model runs in a sandbox with no secrets and no internal network access.

**8.3 AI output is treated as untrusted.** Model output is escaped before display and never executed as code, SQL, shell commands or rendered as raw HTML; links and images in output can't exfiltrate data (markdown image URLs to attacker domains).

**8.4 No secrets in prompts or client code.** Provider keys live server-side behind your own authenticated endpoint (never in the browser or mobile app). System prompts contain no keys, internal URLs or private data, and assume users may extract them.

**8.5 AI memory and retrieval are per-user.** Chat history, vector stores, embeddings and any RAG index are isolated per user or tenant, and retrieval respects the same access control as the source documents.

**8.6 Personal data sent to AI providers is minimised.** Only necessary personal data goes to the model; the provider's data-retention and training settings have been checked; the privacy policy names AI providers (13.1).

---

## Area 9: Multi-tenant SaaS
Applies when one deployment serves multiple customers, organisations, teams or workspaces.

**9.1 Tenant isolation at the data layer.** Every query, cache key, search index, file path, background job and export is scoped by tenant; tenant ID comes from the authenticated session, never from a client-supplied field or header. Prefer defence in depth: database row-level security or per-tenant query scoping that can't be forgotten. Test with two tenants (human checklist H5).

**9.2 Roles and invitations are safe.** Roles are enforced server-side per action (3.7); users can't grant roles above their own; invite tokens are single-use, expiring and bound to the invited email; invites/domain-join can't be used to take over an existing org; removing a member revokes their sessions and keys immediately; the last owner can't be removed by accident.

**9.3 Customer API keys and tokens are handled properly.** Stored hashed (shown once), scoped to least privilege, per-tenant, revocable, with last-used tracking and optional expiry; leaked keys can be rotated without downtime.

**9.4 Outbound webhooks and integrations are safe.** Customer-configured webhook URLs are SSRF-safe (5.4), payloads are signed with a per-tenant secret, delivery retries use backoff (11/12.2), and third-party OAuth tokens are encrypted at rest and scoped narrowly.

**9.5 Admin impersonation and support access are controlled.** "Log in as user" features require staff-only roles, are time-limited, visibly flagged, audit-logged, and can't be used on other staff or to change credentials.

**9.6 SSO/SCIM correctness.** SAML/OIDC validate signatures, audience, issuer and expiry; assertions can't be replayed; email-domain ownership is verified before auto-joining an org; SCIM tokens are scoped and rotatable.

**9.7 Tenant lifecycle.** Data export and deletion work per tenant, deletion reaches backups/search/analytics within a stated period, and a cancelled tenant's access, keys and integrations stop. Audit logs of important tenant actions are available to admins.
