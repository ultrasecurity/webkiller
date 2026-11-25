<p align="center">
  <img src="brand/webkiller-icon.png" width="140" alt="WebKiller logo">
</p>

<h1 align="center">WebKiller 2.0</h1>

<p align="center">
  <b>Agentic recon &amp; exploitation engine for bug-bounty hunters and pentesters.</b><br>
  Point it at a target — it maps the attack surface, and in agent mode tests it and
  <i>confirms findings with proof</i>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-7CFF3A">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-2a3346">
  <img src="https://img.shields.io/badge/license-Noncommercial-F0243E">
  <img src="https://img.shields.io/badge/by-Ultra%20Security%20Team-1C2230">
</p>

---

> **Authorized testing only.** WebKiller is an offensive security tool. Use it only
> against assets you own or are explicitly permitted to test. See
> [DISCLAIMER.md](DISCLAIMER.md).

## What is WebKiller?

WebKiller 2.0 is a complete rewrite of the classic Ultra Security recon tool as a
**local-first desktop application** (Electron). It is a single app that discovers a
target's attack surface, maps it, and — when you let it — actively tests for
vulnerabilities and proves them with evidence.

It runs entirely on your machine (the engine binds to `127.0.0.1` only) and drives
a curated toolkit of best-in-class open-source scanners behind one clean UI, with an
optional **AI agent** that decides which steps to run for a given target.

## Two ways to run

- **🧭 Classic recon** — a fixed, transparent pipeline you control module by module.
  Pick a profile (`passive` → `quick` → `full` → `aggressive`) and WebKiller runs
  exactly those modules, streaming results live.
- **◇ AI Agent (beta)** — give it a target and a scope (recon-only or active tests)
  and the agent picks the steps itself, chains tools, and reports only **confirmed**
  findings with proof-of-concept. You bring your own model via any OpenAI-compatible
  provider (e.g. OpenRouter).

## Features

**Discovery** — passive & active subdomain enumeration, permutations, live-host
probing, port scanning, favicon/TLS-cert pivoting, ASN → CIDR expansion, cloud-bucket
probing, GitHub dorking, DNS OSINT.

**Mapping** — URL collection & crawling, content & parameter discovery, JavaScript
analysis (endpoints & secrets), archive/robots/Wayback mining, OpenAPI route
discovery, tech & WAF fingerprinting, screenshots.

**Checks (active testing)** — service-version → CVE leads with verification, a Nuclei
signal pass, and confirmation modules for **XSS, SQLi, SSTI, LFI, SSRF, XXE,
insecure deserialization, JWT, mass assignment, NoSQLi, CORS, open redirect,
prototype pollution, GraphQL**, and leaked-secret verification.

**Built in** — managed install & detection of the underlying tools, per-module
settings, out-of-scope controls, live SSE progress, rich result views, and an
agent "playbook" that shows what the agent may reach for.

> Active/intrusive checks are **off by default** and gated behind the `aggressive`
> profile (classic) or the *Active tests* scope (agent). Recon is non-destructive.

## Install

Grab the build for your platform from the [**Releases**](../../releases/latest) page.

| Platform | Download |
| --- | --- |
| **Windows** (most PCs, 64-bit) | `WebKiller-2.0.0-win.zip` |
| **Windows** (ARM64) | `WebKiller-2.0.0-arm64-win.zip` |
| **Windows** (32-bit, x86) | `WebKiller-2.0.0-ia32-win.zip` |
| **macOS** (Apple Silicon) | `WebKiller-2.0.0-arm64-mac.zip` |

Unzip and run. The builds are **unsigned**, so your OS may warn on first launch:

- **Windows** — SmartScreen → *More info* → *Run anyway*.
- **macOS** — right-click the app → *Open* (once), or run
  `xattr -cr /Applications/WebKiller.app` if Gatekeeper blocks it.

### Run from source

```bash
git clone https://github.com/ultrasecurity/webkiller.git
cd webkiller
npm install
npm start
```

Requires Node.js 18+. The underlying scanners (subfinder, httpx, nuclei, nmap,
ffuf, dalfox, …) can be installed from inside the app's **Settings → Tools** panel,
which detects what you already have.

## Using it

1. Launch WebKiller and enter a target domain.
2. Add anything out of scope (one host per line).
3. Pick **Classic** (choose a profile) or **AI Agent** (choose recon-only or active).
4. Launch, and watch the run stream live. Open **Results** for the full report.

For AI Agent mode, set a provider key in **Settings → AI** first (any
OpenAI-compatible endpoint; OpenRouter works well). Note that recon data is sent to
that provider, so it leaves your machine — run a local model for sensitive targets.

## License

WebKiller is released under the **PolyForm Noncommercial License 1.0.0** — free for
personal, research, educational, and other **noncommercial** use. **Commercial use is
not permitted** under this license; contact the Ultra Security Team for commercial
licensing. See [LICENSE](LICENSE).

## Credits

Built by the **Ultra Security Team**.

- 🌐 Website: [ultrasec.org](https://ultrasec.org)
- ✈️ Telegram: [@UltraSecurity](https://t.me/UltraSecurity)

WebKiller stands on the shoulders of the open-source security community — subfinder,
httpx, dnsx, naabu, nmap, nuclei, katana, gau, ffuf, dalfox, ghauri, arjun, wafw00f,
gowitness, trufflehog, and many more. Thank you.
