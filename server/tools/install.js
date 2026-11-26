// ============================================================
// Install core — download a pinned release asset, verify its
// SHA256, extract ONLY the one member, and place it atomically in
// the app's managed tools dir. No shell-out to tar/unzip.
//
//   userData/tools/<id>/<version>/<bin>
//
// Install "succeeds" only if detect() afterwards reports that tool
// as a managed, usable candidate — the caller re-detects.
// ============================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { spawnSync } = require('child_process');

function loadLock() { try { return require('./tools.lock.json'); } catch { return { tools: {} }; } }
function managedRoot(over) { return over || path.join(os.homedir(), '.webkiller', 'tools'); }

// ---- download (global fetch; Electron main should pass a net.fetch-backed fetcher for proxy support) ----
async function download(url, destPath, fetcher, onProgress) {
  const f = fetcher || fetch;
  const r = await f(url, { headers: { 'User-Agent': 'webkiller' }, redirect: 'follow' });
  if (!r.ok) throw new Error(`download failed ${r.status} for ${url}`);
  const total = Number(r.headers.get('content-length') || 0);
  const out = fs.createWriteStream(destPath);
  const reader = r.body.getReader();
  let got = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out.write(Buffer.from(value));
    got += value.length;
    if (onProgress && total) onProgress(got / total);
  }
  await new Promise((res, rej) => out.end(e => (e ? rej(e) : res())));
  return destPath;
}

function sha256File(p) {
  return new Promise((res, rej) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(p).on('data', d => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej);
  });
}

// ---- zip: extract a single member (uses the existing yauzl dep) ----
function extractZipMember(zipPath, member, destPath) {
  const yauzl = require('yauzl');
  return new Promise((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true }, (err, zip) => {
      if (err) return reject(err);
      let found = false;
      zip.on('entry', entry => {
        const base = entry.fileName.split('/').pop();
        if (base === member || entry.fileName === member) {
          found = true;
          zip.openReadStream(entry, (e, rs) => {
            if (e) return reject(e);
            const ws = fs.createWriteStream(destPath);
            rs.pipe(ws); ws.on('close', () => resolve(destPath)); ws.on('error', reject);
          });
        } else zip.readEntry();
      });
      zip.on('end', () => { if (!found) reject(new Error(`member "${member}" not found in zip`)); });
      zip.on('error', reject);
      zip.readEntry();
    });
  });
}

// ---- tar.gz: parse ustar headers in-memory, extract one member (archives are small) ----
function extractTarGzMember(tgzPath, member, destPath) {
  const buf = zlib.gunzipSync(fs.readFileSync(tgzPath));
  let off = 0;
  while (off + 512 <= buf.length) {
    const header = buf.subarray(off, off + 512); off += 512;
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    if (!name) continue;
    const size = parseInt(header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim(), 8) || 0;
    const base = name.split('/').pop();
    if (base === member || name === member) { fs.writeFileSync(destPath, buf.subarray(off, off + size)); return destPath; }
    off += Math.ceil(size / 512) * 512;
  }
  throw new Error(`member "${member}" not found in tar.gz`);
}

function stripQuarantine(p) {
  if (process.platform === 'darwin') { try { spawnSync('xattr', ['-d', 'com.apple.quarantine', p], { timeout: 4000 }); } catch { /* defensive, ignore */ } }
}

// Install one tool. opts: { platform, managedDir, fetcher, onProgress }
async function installTool(id, opts = {}) {
  const { platformKey } = require('./detect');
  const platform = opts.platform || platformKey();
  const entry = (opts.lock || loadLock()).tools[id];
  if (!entry) throw new Error(`no lock entry for ${id} — run genlock`);
  const asset = entry.assets[platform];
  if (!asset || asset.missing || !asset.url) throw new Error(`no download for ${id} on ${platform}`);

  const root = managedRoot(opts.managedDir);
  const finalDir = path.join(root, id, entry.version);
  const finalBin = path.join(finalDir, asset.member);
  const staging = path.join(root, '.staging', `${id}-${process.pid}-${Date.now()}`);
  fs.mkdirSync(staging, { recursive: true });
  try {
    const dl = path.join(staging, 'asset.bin');
    if (opts.onPhase) opts.onPhase('downloading');
    await download(asset.url, dl, opts.fetcher, opts.onProgress);

    if (asset.sha256) {
      if (opts.onPhase) opts.onPhase('verifying');
      const got = await sha256File(dl);
      if (got !== asset.sha256) { const e = new Error(`checksum mismatch for ${id}: expected ${asset.sha256.slice(0, 12)}…, got ${got.slice(0, 12)}…`); e.code = 'HASH_MISMATCH'; throw e; }
    }

    if (opts.onPhase) opts.onPhase('extracting');
    const stagedBin = path.join(staging, asset.member);
    fs.mkdirSync(path.dirname(stagedBin), { recursive: true });
    if (asset.archive === 'zip') await extractZipMember(dl, asset.member, stagedBin);
    else if (asset.archive === 'tar.gz') extractTarGzMember(dl, asset.member, stagedBin);
    else fs.copyFileSync(dl, stagedBin); // raw
    fs.chmodSync(stagedBin, 0o755);
    stripQuarantine(stagedBin);

    // atomic place: fresh version dir, move the binary in
    fs.mkdirSync(path.join(root, id), { recursive: true });
    fs.rmSync(finalDir, { recursive: true, force: true });
    fs.mkdirSync(finalDir, { recursive: true });
    fs.renameSync(stagedBin, finalBin);
    fs.chmodSync(finalBin, 0o755);
    return { id, version: entry.version, path: finalBin, sha256: asset.sha256 };
  } finally {
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

function uninstallTool(id, opts = {}) {
  const dir = path.join(managedRoot(opts.managedDir), id);
  fs.rmSync(dir, { recursive: true, force: true });
}

module.exports = { installTool, uninstallTool, managedRoot, loadLock, download, sha256File, extractZipMember, extractTarGzMember };
