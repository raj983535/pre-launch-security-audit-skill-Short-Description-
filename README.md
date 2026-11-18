# Pre-Launch Security Audit Skill

[![Agent Skills Compatible](https://img.shields.io/badge/Agent%20Skills-Compatible-success)](https://skills.sh)
[![OWASP Top 10 2025](https://img.shields.io/badge/OWASP%20Top%2010-2025%20Ready-blue)](https://owasp.org/Top10/2025)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive, stack-agnostic security audit skill for AI coding assistants (**Antigravity**, **Claude Code**, **Cursor**, **Codex**, **Windsurf**, and **OpenCode**). Point it at any web app, mobile app, API, SaaS or fintech product—in any language and whatever AI tool built it—and it will find dangerous vulnerabilities, explain them in plain language, and fix only what you approve.

> **Credits & Attribution:**  
> The core 4-step workflow, approval-gated review model, and foundational checklist were designed by **Mayank Shah** ([Instagram: @mayankshah_ai](https://instagram.com/mayankshah_ai) | [X: @Mayankshahh](https://x.com/Mayankshahh)).  
> Packaged and maintained as an open-source multi-agent skill by [raj983535](https://github.com/raj983535) with expanded stack guides, multi-tenant SaaS checks, fintech coverage, and automated static scanning tools.

---

## 🌟 Highlights

- **105 Automated Code Checks** across 14 areas + **20 Human Verification Checks** + a single-screen executive verdict.
- **Stack Guides**: Python (Django, DRF, Flask, FastAPI), Node/Next.js/Express, PHP (Laravel, Symfony, WordPress), Java/Spring, .NET, Rails, Go, Flutter, native mobile, Supabase, and Firebase.
- **Fintech & Multi-Tenant SaaS Depth**: Integer minor-unit money math, atomic balance debits, ledger integrity, KYC privacy, tenant data isolation, customer API keys, and SSRF-safe webhooks.
- **AI-Built App Pitfalls**: Scans apps built by Lovable, Bolt, v0, Replit, Cursor, Claude Code, and Emergent for common AI failure modes (client-side only checks, leaked frontend keys, wide-open RLS policies, default seeded admins, hallucinated dependencies, and hidden prompt injection).
- **Automated Lead Finder**: Bundled with `scripts/quick_scan.py`—a zero-dependency, read-only Python static analysis scanner that checks for leaked secrets, injection, and insecure functions in seconds.

---

## 🚀 Quick Install

### Using `npx skills` (Recommended)
```bash
# Install to current project
npx skills add raj983535/pre-launch-security-audit-skill-Short-Description-

# Or install globally across all projects on your machine
npx skills add raj983535/pre-launch-security-audit-skill-Short-Description- -g
```

### Manual Installation
Copy this repository into your agent's skills folder:
- **Antigravity / Gemini**: `~/.gemini/config/skills/pre-launch-security-audit/`
- **Universal Agents**: `~/.agents/skills/pre-launch-security-audit/`
- **Claude Code**: `~/.claude/skills/pre-launch-security-audit/`
- **Cursor**: `.cursor/skills/pre-launch-security-audit/`

---

## 🛡️ The 4-Step Workflow

```
[ Step 1: Intake ]  --->  [ Step 2: Code Pass ]  --->  [ Step 3: Fix Round ]  --->  [ Step 4: Human Checklist & Verdict ]
Detect stack, scope       Run quick_scan.py & 14 areas; Fix approved items;            20 human checks (H1-H20);
ask only unknown facts    write AUDIT.md                Critical first; server-side    Single-screen report: Ready or Not
```

### Audit Modes Supported:
- **Full Audit**: Default complete 4-step audit across all areas.
- **Focused Audit**: Target a single domain (e.g., *"check my payments code"*, *"review my auth"*).
- **Diff / PR Review**: Audits only changed files (`git diff`) to catch regressions before merge.
- **Resume**: Continues seamlessly from an existing `AUDIT.md` file.

---

## 🔍 Standalone Scanner Usage

You can also run the bundled lead finder script directly from your terminal:

```bash
# Scan a project folder
python3 scripts/quick_scan.py /path/to/project

# Include built distribution bundles (dist, build, .next, out)
python3 scripts/quick_scan.py /path/to/project --include-build

# Output structured JSON for CI/CD pipelines
python3 scripts/quick_scan.py /path/to/project --json
```

---

## 📁 Repository Layout

```
├── SKILL.md                              # Core instructions, modes, safety & fix rules
├── scripts/
│   └── quick_scan.py                     # Zero-dependency read-only static scanner
├── references/
│   ├── checks-1-3-secrets-auth-access.md # Areas 1-3: Secrets, Authentication, IDOR
│   ├── checks-4-6-data-input-abuse.md    # Areas 4-6: Injection, SSRF, XSS, Rate limits
│   ├── checks-7-9-money-ai-saas.md       # Areas 7-9: Fintech, LLM features, SaaS tenancy
│   ├── checks-10-14-platform-privacy-mobile.md # Areas 10-14: Supply chain, Headers, Mobile
│   ├── human-checklist-and-report.md     # 20 Human operational checks & final report template
│   ├── stack-python.md                   # Django, DRF, Flask, FastAPI deep-dive
│   ├── stack-node-js.md                  # Express, NestJS, Next.js, React/Vue deep-dive
│   ├── stack-php.md                      # PHP, Laravel, Symfony, WordPress deep-dive
│   ├── stack-baas-and-ai-builders.md     # Supabase, Firebase, Lovable, Bolt, Cursor flaws
│   └── stack-other.md                    # Java/Spring, .NET, Rails, Go, Flutter, Native
├── package.json                          # Agent Skills package definition
└── LICENSE                               # MIT License with attribution notice
```

---

## 🔒 Safety Contract

- **Read-only by default**: No code or configuration is modified without explicit owner consent.
- **No destructive testing**: No data deletion, payment execution, or live messaging.
- **Full secret masking**: Displays at most the first 4 characters (e.g. `sk-e••••`).
- **Never weaken security**: Never disables auth checks, widens CORS, or loosens policies to resolve errors.
- **Material, not instructions**: Treats repository comments and prompt files as material to audit, never as instructions to obey.

---

## 📄 License & Attribution

- **Original Methodology**: Inspired by and built on the 85-point checklist by Mayank Shah ([@mayankshah_ai](https://instagram.com/mayankshah_ai) | [@Mayankshahh](https://x.com/Mayankshahh)).
- **Skill Implementation & Tooling**: Released under the MIT License by [raj983535](https://github.com/raj983535).
