// Shared User-Agent presets for the scanner's target-facing requests.
//
// Policy: WebKiller must NEVER announce itself to a scan target. The UA a target
// sees is always a real, common browser string (or the user's own custom value) —
// never a "WebKiller/*" identifier. Internal API etiquette UAs (GitHub, NVD) live
// at their own call sites and are intentionally NOT governed here.
//
// Stored value semantics (server-side):
//   - a concrete preset value  -> used as-is
//   - the RANDOM sentinel       -> resolved to a random preset per scan
//   - '' or a legacy WebKiller* -> resolved to DEFAULT_UA (migrates old saves)

const PRESETS = [
  { label: 'Chrome · Windows',  value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' },
  { label: 'Chrome · macOS',    value: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' },
  { label: 'Safari · macOS',    value: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15' },
  { label: 'Firefox · Windows', value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0' },
  { label: 'Edge · Windows',    value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0' },
  { label: 'Chrome · Android',  value: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36' },
  { label: 'Safari · iPhone',   value: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1' },
];

const RANDOM = '__random__';
const DEFAULT_UA = PRESETS[0].value; // Chrome on Windows — the single most common UA, best for blending in

function pickRandom() {
  return PRESETS[Math.floor(Math.random() * PRESETS.length)].value;
}

// Old WebKiller-branded defaults that may still be sitting in a saved config.
function isLegacyBrand(v) {
  return typeof v === 'string' && /^webkiller/i.test(v.trim());
}

// For actual requests: random -> a concrete UA, empty/legacy -> the default.
function resolveUA(v) {
  if (v === RANDOM) return pickRandom();
  if (!v || isLegacyBrand(v)) return DEFAULT_UA;
  return v;
}

// For the Settings UI: keep the RANDOM sentinel (so the select shows "Random"),
// but never surface an empty or legacy-branded value.
function displayUA(v) {
  if (v === RANDOM) return RANDOM;
  if (!v || isLegacyBrand(v)) return DEFAULT_UA;
  return v;
}

module.exports = { PRESETS, RANDOM, DEFAULT_UA, pickRandom, resolveUA, displayUA, isLegacyBrand };
