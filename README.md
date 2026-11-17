# Pre-Launch Security Audit Skill (85 Checks)

[![Agent Skills Compatible](https://img.shields.io/badge/Agent%20Skills-Compatible-success)](https://skills.sh)
[![OWASP Top 10 2025](https://img.shields.io/badge/OWASP%20Top%2010-2025%20Ready-blue)](https://owasp.org/Top10/2025)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An open-source, universal **Pre-Launch Security Audit Skill** for AI coding assistants (Claude Code, Antigravity, Cursor, Codex, Windsurf, OpenCode, and Gemini CLI).

Based on the battle-tested methodology by Mayank Shah and mapped against **OWASP Top 10 (2025)**, **OWASP Top 10 for LLM Applications (2025)**, and modern mobile/web security baselines.

---

## 🚀 Quick Install

### Using `npx skills` (Recommended)
```bash
# Install to your current project
npx skills add raj983535/pre-launch-security-audit-skill-Short-Description-

# Or install globally across all projects on your machine
npx skills add raj983535/pre-launch-security-audit-skill-Short-Description- -g
```

### Manual Installation
Copy the `SKILL.md` file into your agent's global or project skills directory:
- **Antigravity / Gemini**: `~/.gemini/config/skills/pre-launch-security-audit/SKILL.md`
- **Universal Agents**: `~/.agents/skills/pre-launch-security-audit/SKILL.md`
- **Claude Code**: `~/.claude/skills/pre-launch-security-audit/SKILL.md`
- **Cursor**: `.cursor/skills/pre-launch-security-audit/SKILL.md`

---

## 🛡️ What It Covers

This skill equips your AI assistant with **85 comprehensive checks** divided into 4 execution steps:

1. **Step 1: Intake & Scope Detection**  
   Automatically detects your technology stack (Web, Mobile, Backend API, Database, Payments, AI integrations) and asks only what the code cannot reveal.
2. **Step 2: 67 Automated Code Checks**  
   Scans your code across 13 distinct security categories and writes detailed technical findings to `AUDIT.md`.
3. **Step 3: Supervised Fix Round**  
   Fixes only user-approved vulnerabilities (Critical/High first) with minimal, surgical server-side patches.
4. **Step 4: 18 Human Checks & Executive Report**  
   Runs through operational verification (2FA, spending caps, backups, legal terms) and outputs a single-screen launch verdict.

---

## 📋 The 13 Security Categories (67 Code Checks)

| Category | Checks | Focus Areas |
| :--- | :---: | :--- |
| **01. Secrets & API Keys** | 4 | Client-side bundles, Git history, secret manager usage, telemetry leakage |
| **02. Login & Sessions** | 7 | Server auth verification, Argon2/bcrypt hashing, JWT expiry, brute-force protection |
| **03. Access Control (IDOR)** | 6 | Object-level ownership filters, mass assignment prevention, admin role isolation |
| **04. Database & Storage** | 5 | NoSQL/SQL injection prevention, UUID vs ObjectId, private S3/GCS buckets, RLS policies |
| **05. Input & Output Handling**| 6 | Server schema validation (Pydantic/Zod), XSS sanitization, SSRF protection, safe errors |
| **06. API Abuse Protection** | 6 | Distributed rate limiting (Redis/DB), strict CORS allowlists, Turnstile CAPTCHA, CSRF |
| **07. Payments & Financial** | 6 | Server-authoritative pricing, webhook signature verification, atomic credit updates |
| **08. AI & LLM Features** | 5 | Token quotas, prompt injection defenses, untrusted LLM outputs, isolated multi-tenant RAG |
| **09. Supply Chain** | 4 | Dependency audit (`npm audit`/`pip-audit`), lockfile pinning, prompt injection in packages |
| **10. Deployment Config** | 5 | Essential security headers (`nosniff`, `frame-ancestors`), debug off, protected `/docs` |
| **11. Cost & Code Health** | 3 | Aggressive polling elimination, runaway recursive loops, dead fallback route cleanup |
| **12. Privacy & Compliance** | 3 | Privacy policy/terms, cookie consent for EU/DPDP, complete account deletion pipeline |
| **13. Mobile Security (Expo)** | 7 | SecureStore / Keystore, cleartext traffic blocking, deep link validation, WebView lockdown |

---

## 🧑‍💻 The 18 Human Verification Checks (H1 to H18)

- **H1**: Chat/ticket secret leak rotation
- **H2**: Cloud & LLM hard spending limits
- **H3**: Public GitHub repository exposure
- **H4**: 2FA enforcement across dashboards
- **H5**: Two-account cross-tenant IDOR test
- **H6**: Unnecessary data minimization
- **H7**: Tested database backup and restore drill
- **H8**: Supabase / Firebase advisor alerts
- **H9**: Refund & commercial invoicing compliance
- **H10**: AI provider data retention policies
- **H11**: Test data segregated from live production
- **H12**: Registrar 2FA & email SPF/DKIM/DMARC
- **H13**: Verified 60-second rollback procedure
- **H14**: Error alerting & uptime monitoring
- **H15**: Under-18 child privacy (COPPA / DPDP)
- **H16**: Email unsubscribe & marketing opt-in
- **H17**: App Store / Play Store privacy label accuracy
- **H18**: Remote force-update capability for mobile

---

## 🔒 Safety Contract for AI Agents

Agents running this skill must adhere to non-negotiable safety rules:
- **Read-Only by default**: Never apply changes without explicit user approval.
- **Mask all secrets**: Display at most the first 4 characters (e.g. `sk-e••••`).
- **No destructive actions**: Never delete production data or trigger live payments.
- **Never weaken security**: Never remove authentication or widen CORS to resolve an error.

---

## 📄 License

MIT License. Designed for open distribution across the agentic developer ecosystem.
