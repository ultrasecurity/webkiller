<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="brand/webkiller-banner-light.png">
    <source media="(prefers-color-scheme: dark)" srcset="brand/webkiller-banner.png">
    <img alt="WebKiller — agentic recon & exploitation engine" src="brand/webkiller-banner.png">
  </picture>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%20·%20macOS%20·%20Linux-2a3346">
  <img src="https://img.shields.io/badge/license-Noncommercial-F0243E">
  <img src="https://img.shields.io/badge/by-Ultra%20Security%20Team-1C2230">
</p>

---

> ⚠️ **Authorized testing only.** Point WebKiller at assets you own or have permission to test. See the [disclaimer](DISCLAIMER.md).

Most recon tools hand you a wall of output and walk away. **WebKiller doesn't.**

Aim it at a target and it maps the whole attack surface for you — subdomains, live hosts, open ports, endpoints, tech stack, the lot. Then, if you let it off the leash, an **AI agent** goes hunting: it chains the tools itself, actually tests what it finds, and hands you only the bugs it could *prove*.

It's a desktop app, and everything runs on your machine — the engine never leaves `127.0.0.1`.

## Two ways to hunt

**🧭 Classic** — you're driving. Choose how deep to go (`passive` → `aggressive`) and WebKiller runs a clean, predictable pipeline, module by module, streaming results as they land.

**◇ AI Agent** — hand it a target and a leash length (recon-only, or active testing) and let it work. It decides what matters, follows the interesting threads, and reports confirmed findings with proof — not a pile of maybes. Bring any OpenAI-compatible model; OpenRouter works great.

## Under the hood

- **Find** — subdomains (passive + brute-force), live-host probing, port scans, favicon & TLS-cert pivots, ASN → CIDR, cloud buckets, GitHub dorks, DNS OSINT.
- **Map** — URL & endpoint collection, content & parameter discovery, secrets in JavaScript, Wayback mining, OpenAPI routes, tech/WAF fingerprinting, screenshots.
- **Prove** — XSS, SQLi, SSTI, LFI, SSRF, XXE, deserialization, JWT, mass assignment, NoSQLi, CORS, open redirect, prototype pollution, GraphQL, and leaked-secret verification — on top of service-CVE matching and a Nuclei pass.

Active checks stay **off until you ask for them** — recon never fires a payload. WebKiller also installs and manages the underlying toolkit for you, so there's no dependency rabbit hole.

## Get it

Grab the build for your machine from the [**Releases**](../../releases/latest) page:

| Your machine | Grab |
| --- | --- |
| Windows — 64-bit (most PCs) | the `…-win.zip` |
| Windows — ARM64 | the `…-arm64-win.zip` |
| Windows — 32-bit | the `…-ia32-win.zip` |
| macOS — Apple Silicon | the `…-arm64-mac.zip` |

Unzip and run. Builds aren't code-signed yet, so the first launch needs a nudge: on Windows, SmartScreen → *More info → Run anyway*; on macOS, right-click → *Open* (or `xattr -cr WebKiller.app`).

**Prefer source?**

```bash
git clone https://github.com/ultrasecurity/webkiller.git
cd webkiller && npm install && npm start
```

## Using it

Type a target, mark anything out of scope, pick Classic or Agent, and launch. Watch it work live — the full report is waiting in **Results**. For Agent mode, drop a provider key into **Settings → AI** first, and keep in mind that recon data goes to whatever model you point it at, so reach for a local one on sensitive work.

## License

Free for **noncommercial** use under the [PolyForm Noncommercial License](LICENSE). Using WebKiller to make money needs a commercial license — talk to the Ultra Security Team.

## Built by Ultra Security Team

🌐 [ultrasec.org](https://ultrasec.org) · ✈️ [@UltraSecurity](https://t.me/UltraSecurity)

Standing on the shoulders of the open-source security community — subfinder, httpx, nuclei, nmap, ffuf, dalfox, and many more. Respect.
