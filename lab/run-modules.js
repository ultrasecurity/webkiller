// Runs WebKiller's active modules against the running vuln-lab and prints what
// each level detected. Assumes `node lab/vuln-lab.js` is already running.
//   NATIVE=1  -> force native code paths (ignore installed dalfox/ghauri)
const fs = require('fs'); const os = require('os'); const path = require('path');
const WK = path.resolve(__dirname, '..', 'server');
const OUT = fs.mkdtempSync(path.join(os.tmpdir(), 'wk-lab-'));
process.env.WEBKILLER_OUTPUT_DIR = OUT;

if (process.env.NATIVE) { const reg = require(WK + '/registry'); reg.isInstalled = () => false; }

const { Workspace } = require(WK + '/workspace');
const { Scope } = require(WK + '/scope');
const { getConfig } = require(WK + '/config');

const PORT = Number(process.env.VPORT || 8900);
const b = `http://127.0.0.1:${PORT}`;
const UUID = '7b2e4c10-0000-4000-8000-000000000001';

const ws = new Workspace('127.0.0.1', 'lab');
ws.appendLines('urls.txt', [
  ...[1, 2, 3, 4].map((l) => `${b}/xss/${l}?q=test`),
  ...[1, 2, 3, 4].map((l) => `${b}/sqli/${l}?id=1`),
  `${b}/api/v1/user/1`, `${b}/api/v2/user/1`, `${b}/api/v3/doc/${UUID}`, `${b}/api/v4/user/1`,
]);
ws.appendLines('params.txt', [...[1, 2, 3, 4].map((l) => `${b}/xss/${l}?q=test`), ...[1, 2, 3, 4].map((l) => `${b}/sqli/${l}?id=1`)]);
ws.appendJsonl('findings.jsonl', [1, 2, 3, 4].map((l) => ({ url: `${b}/secret/${l}`, status_code: 403 })));

const scope = new Scope(['127.0.0.1'], null);
const config = getConfig();
const emit = () => {};
const mods = {
  xss_confirm: require(WK + '/modules/xss_confirm'),
  sqli_confirm: require(WK + '/modules/sqli_confirm'),
  authz_probe: require(WK + '/modules/authz_probe'),
  bypass_403: require(WK + '/modules/bypass_403'),
};

(async () => {
  console.log(process.env.NATIVE ? '### NATIVE logic ###' : '### with installed tools ###');
  for (const [n, M] of Object.entries(mods)) {
    const s = Date.now();
    let r; try { r = await new M(ws, scope, config, emit).run(); } catch (e) { console.log(`\n${n}: ERROR ${e.message}`); continue; }
    const recs = (r.records && r.records.length) ? r.records : [];
    console.log(`\n${n}  (${((Date.now() - s) / 1000).toFixed(1)}s, tool=${r.toolUsed || '-'})`);
    if (!recs.length) { console.log('   (no findings)'); continue; }
    recs.forEach((x) => console.log(`   ✔ ${(x.vuln_class || x.name)} [${x.severity}]  ${(x.url || '').replace(b, '')}`));
  }
  fs.rmSync(OUT, { recursive: true, force: true });
})();
