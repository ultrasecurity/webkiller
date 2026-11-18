# WebKiller Vuln Lab

A **deliberately vulnerable** web app for testing WebKiller's active modules (and dalfox / ghauri) against a **known, authorized** target. It binds to `127.0.0.1` only — never expose it.

Each vulnerability class has **4 levels**:

| Level | Meaning |
|---|---|
| **L1** | Naked — a single simple payload triggers it |
| **L2** | Light filter — needs an alternate payload |
| **L3** | Stronger filter / obfuscation — needs advanced payloads |
| **L4** | Properly patched — must **not** be detectable (false-positive control) |

## Run

```bash
node lab/vuln-lab.js            # serves on 127.0.0.1:8900 (VPORT to change)
```

Then exercise it with the module runner (uses WebKiller's own modules):

```bash
NATIVE=1 node lab/run-modules.js      # force native logic (deterministic)
node lab/run-modules.js               # use installed tools (dalfox/ghauri) if present
```

## Endpoints

| Class | URL | Vulnerable thing |
|---|---|---|
| Reflected XSS | `/xss/{1-4}?q=` | L1 raw · L2 strips `<script` only · L3 `<>` encoded but inside a `value="…"` attribute (quote breakout) · L4 input not reflected |
| Time-based SQLi | `/sqli/{1-4}?id=` | L1 any sleep keyword · L2 blocks `sleep` (WAITFOR/BENCHMARK survive) · L3 WAF blocks plain keywords, DB runs comment-obfuscated (`sl/**/eep`) · L4 parameterized |
| IDOR / BAC | `/api/v{1-4}/user/{id}` (L3 = `/api/v3/doc/{uuid}`) | L1 no auth, sequential, write methods accepted · L2 session-gated · L3 non-sequential UUID ids · L4 ownership-checked |
| 403 bypass | `/secret/{1-4}` | L1 any path variant or header · L2 header only · L3 path trick only (`..;/`, `/%2e/`, `/.`) · L4 fully blocked |

## Expected WebKiller (native) detection

- **XSS** reflection check flags L1–L3 (any reflection); L4 clean. Note: reflection ≠ XSS — L3 (attribute context) and encoded reflections need dalfox/manual to confirm exploitability.
- **SQLi** (native 3 payloads) catches L1 and L2 (WAITFOR survives); L3 needs obfuscated payloads (ghauri); L4 clean.
- **Broken access** — L1 full (auth-diff + IDOR + method tampering); L2 needs auth (unauthenticated scan misses it); L3 flagged via response-diff but sequential-IDOR misses the UUID; L4 clean.
- **403 bypass** — L1–L3 bypassed by the payload set; L4 clean.

This gradient is the point: L1 proves detection fires, L2/L3 stress payload coverage, L4 confirms no false positives.
