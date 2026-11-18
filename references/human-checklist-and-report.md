# Step 4: Human checklist and final report

## Contents
- Human checklist (20 items)
- Final report (one screen)
- Key-leak playbook (generic)

---

## Human checklist
Send in ONE message, only the items that apply to this product (skip mobile items for a web app, Supabase/Firebase for others, payments items if no payments). **ASK** = the user answers a yes/no or fact. **DO** = the user must go and do something (code can't verify it).

- **H1 ASK** Have you ever pasted an API key, password or token into an AI chat, WhatsApp, Slack, email or a support ticket? If yes, rotate it.
- **H2 DO** Spending limits: set a hard cap or budget alert on every paid service (cloud, AI providers, SMS/email, maps). Check whether auto-recharge is on and at what threshold.
- **H3 ASK** Is your Git repository public? If any secret was ever pushed, revoke and replace it. Is secret scanning/push protection on?
- **H4 ASK** Is two-factor authentication on for your hosting/cloud account, Git host, domain registrar, email, payment dashboard, database and app-store accounts?
- **H5 DO** Two-account test in a non-production environment: create accounts A and B (and two tenants if multi-tenant), then try to open, edit and delete B's data while logged in as A. Every attempt should fail.
- **H6 ASK** Do you store anything you don't need (card numbers, ID documents, plain passwords, full logs of personal data)? Delete it or stop collecting it.
- **H7 DO** Backups: confirm how your database and files are backed up, that backups are encrypted and stored separately, and that you have restored one successfully. An untested backup doesn't count.
- **H8 DO** Supabase/Firebase only: check Supabase Dashboard → Advisors → Security Advisor, or your Firebase console rules, and send the AI any warnings.
- **H9 ASK** Do you have a refund policy and correct tax invoicing for the countries you sell in (e.g. GST in India, VAT in the EU)?
- **H10 ASK** Are you sending only necessary personal data to AI models and analytics tools? Have you checked each provider's data-retention and training settings?
- **H11 ASK** Do test accounts, test data and test API keys stay out of production?
- **H12 ASK** Custom domain: is DNS/registrar access locked with 2FA, are old subdomains cleaned up, and do your sending domains have SPF, DKIM and DMARC?
- **H13 ASK** Do you know how to roll back a bad release quickly?
- **H14 ASK** Will you hear about errors and downtime? Error alerts and an uptime monitor set up?
- **H15 ASK** If users could be under 18: do you have an age check and parental consent where the law requires it (COPPA, GDPR, India's DPDP Act)?
- **H16 ASK** Marketing emails have an unsubscribe link and sender details; SMS/WhatsApp marketing goes only to people who opted in?
- **H17 ASK** Mobile only: do your App Store privacy labels and Google Play Data safety form match what the app really collects, including third-party SDKs?
- **H18 ASK** Mobile only: can you force users to update if a security fix ships?
- **H19 ASK** Fintech/payments only: which regulations and scheme rules apply to you (PCI DSS scope, local central-bank or payment-aggregator rules, KYC/AML, PSD2 strong customer authentication)? Has a qualified person confirmed your obligations?
- **H20 ASK** Do you have an incident plan: who is called first, how affected users are told, and how a leaked key or compromised account is shut down within an hour?

---

## Final report (ONE screen)
Send after the user answers the checklist. Keep it to one screen; point to `AUDIT.md` for everything else.

1. **Verdict.** One line, e.g. "Ready to launch after 2 High fixes" or "Not ready: 3 Critical issues open". Never "100% secure".
2. **Counts.** Passed · fixed · still open · need you · skipped.
3. **Open issues.** One line each, Critical first, with who fixes it (AI or user).
4. **Your to-do list.** Every checklist item still open.
5. **Do this on your live app.** Every fix that changed data, a secret, env or config in the non-production environment (deleted default admin, rotated key, cleaned data, new CORS/redirect allowlist), with exact steps to repeat it in production. Include every CAN'T VERIFY item that depends on a live setting.
6. **If a key leaks.** See the playbook below, filled in with this app's real keys and providers.
7. **Security contact.** Add a way to report issues (`/.well-known/security.txt` or an email address) and name who acts if something goes wrong and how affected users are told.
8. **Clean up AUDIT.md.** It lists the app's weaknesses. Delete it now that fixes are done.
9. **When to re-run.** Before every major release, after adding payments, uploads, AI features, a new integration or a new framework/plugin, after any incident, and every 3 months.

Keep the report on one screen. End with this idea in your own words: *"This audit catches the most common and most damaging mistakes, but it isn't a professional penetration test. Before you handle payments or sensitive data at scale, get a human security review."*

---

## Key-leak playbook (generic; adapt to this app's providers)
1. **Identify** which key leaked and what it can do (read data? spend money? send messages?).
2. **Revoke or regenerate** it at the provider's dashboard. Warning: regenerating a key used by several projects breaks every app using the old key, so list every project using it first, then rotate, update and redeploy each one in the same sitting.
3. **Update** the secret where the app reads it (secret manager / environment variables), never in code.
4. **Redeploy** so the new key is live, and clear any caches or build artefacts that contain the old one.
5. **Check damage:** provider usage and billing, access logs, new accounts or API keys created, data exported. Remove the leaked value from Git history only after rotation (rotation is what protects you).
6. **Tell** affected users and regulators if personal data may have been accessed, within legal deadlines.
