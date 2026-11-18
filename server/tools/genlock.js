// ============================================================
// Lock generator — resolves each archive-install tool's real
// release assets (download URL + SHA256 + size, per os×arch) from
// GitHub and writes tools.lock.json. Run this at build time, not
// in the app. The hand-written manifest never carries URLs/hashes.
//
//   node server/tools/genlock.js            # all archive tools
//   node server/tools/genlock.js httpx gau  # only these
//
// Prefers the manifest's pinned tag; falls back to the latest
// release (and records the resolved version) so a stale pin still
// produces a usable, honest lock.
// ============================================================

const fs = require('fs');
const path = require('path');
const { TOOLS, PLATFORMS } = require('./manifest');

const GH = { 'User-Agent': 'webkiller-genlock', Accept: 'application/vnd.github+json' };
// A token (if present in the env) only raises the rate limit; never printed.
if (process.env.GITHUB_TOKEN) GH.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

async function ghJson(url) {
  const r = await fetch(url, { headers: GH });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
}

async function release(repo, version) {
  // Try the v-prefixed tag, then the bare tag (gowitness tags have no "v"),
  // then fall back to latest so a stale/renamed pin still yields a usable lock.
  for (const tag of [`v${version}`, `${version}`]) {
    try { return await ghJson(`https://api.github.com/repos/${repo}/releases/tags/${tag}`); } catch { /* try next */ }
  }
  return ghJson(`https://api.github.com/repos/${repo}/releases/latest`);
}

function parseChecksums(txt) {
  const map = {};
  for (const line of txt.split('\n')) {
    const m = line.trim().match(/^([0-9a-f]{64})\s+[*]?(.+)$/i);
    if (m) map[m[2].trim()] = m[1].toLowerCase();
  }
  return map;
}

async function genTool(id, spec) {
  const inst = spec.install;
  if (!inst || inst.kind !== 'archive') return null;
  const rel = await release(inst.repo, inst.version);
  const ver = String(rel.tag_name || inst.version).replace(/^v/, '');
  const assets = rel.assets || [];
  const sumAsset = assets.find(a => /checksum|sha256|_sums|\.sha256$/i.test(a.name));
  let sums = {};
  if (sumAsset) { const r = await fetch(sumAsset.browser_download_url, { headers: GH }); if (r.ok) sums = parseChecksums(await r.text()); }

  const out = { version: ver, assets: {} };
  for (const p of PLATFORMS) {
    const a = inst.assets[p];
    if (!a) continue;
    const name = a.nameTemplate.replace('{version}', ver);
    const asset = assets.find(x => x.name === name);
    if (!asset) { out.assets[p] = { missing: true, expected: name }; continue; }
    out.assets[p] = { url: asset.browser_download_url, sha256: sums[name] || null, size: asset.size, archive: a.archive, member: a.member };
  }
  return out;
}

async function main(onlyIds) {
  const lockPath = path.join(__dirname, 'tools.lock.json');
  let lock = { schemaVersion: 1, tools: {} };
  try { lock = JSON.parse(fs.readFileSync(lockPath, 'utf8')); } catch { /* fresh */ }
  lock.generatedAt = new Date().toISOString();
  lock.tools = lock.tools || {};

  for (const [id, spec] of Object.entries(TOOLS)) {
    if (onlyIds && onlyIds.length && !onlyIds.includes(id)) continue;
    if (!spec.install || spec.install.kind !== 'archive') continue;
    try {
      const entry = await genTool(id, spec);
      if (entry) {
        lock.tools[id] = entry;
        const ok = Object.values(entry.assets).filter(a => a.url && a.sha256).length;
        const miss = Object.values(entry.assets).filter(a => a.missing).length;
        console.error(`ok   ${id.padEnd(12)} v${entry.version}  ${ok} assets with hash, ${miss} missing`);
      }
    } catch (e) { console.error(`FAIL ${id.padEnd(12)} ${e.message}`); }
  }
  fs.writeFileSync(lockPath, JSON.stringify(lock, null, 2));
  console.error('wrote', lockPath);
}

if (require.main === module) {
  const args = process.argv.slice(2);
  main(args).catch(e => { console.error(e); process.exit(1); });
}
module.exports = { main, genTool };
