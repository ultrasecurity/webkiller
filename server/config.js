const path = require('path');
const fs = require('fs');
const yaml = require('js-yaml');
const { DEFAULT_UA } = require('./user_agents');

function getBaseDir() {
  if (process.resourcesPath && fs.existsSync(path.join(process.resourcesPath, 'app.asar.unpacked'))) {
    return path.join(process.resourcesPath, 'app.asar.unpacked');
  }
  return path.resolve(__dirname, '..');
}

const BASE_DIR = getBaseDir();
const PROFILES_DIR = path.join(BASE_DIR, 'profiles');
const OUTPUT_DIR = process.env.WEBKILLER_OUTPUT_DIR || path.join(BASE_DIR, 'output');
const WORDLISTS_DIR = path.join(BASE_DIR, 'wordlists');
const RESOLVERS_DIR = path.join(BASE_DIR, 'resolvers');

const DEFAULT_CONFIG = {
  concurrency: 20,
  rate_limit: 50,
  timeout: 30,
  user_agent: DEFAULT_UA,
  bug_bounty_header: '',
  resolvers_file: '',
  notify: { enabled: false, webhook: '' },
  interactsh: { enabled: false, server: '' },
};

function loadProfile(name) {
  const filePath = path.join(PROFILES_DIR, `${name}.yaml`);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Profile not found: ${name}`);
  }
  return yaml.load(fs.readFileSync(filePath, 'utf8'));
}

function listProfiles() {
  if (!fs.existsSync(PROFILES_DIR)) return [];
  return fs.readdirSync(PROFILES_DIR)
    .filter(f => f.endsWith('.yaml'))
    .map(f => f.replace('.yaml', ''));
}

function getConfig(overrides) {
  const cfg = { ...DEFAULT_CONFIG };
  if (overrides) Object.assign(cfg, overrides);
  return cfg;
}

module.exports = {
  BASE_DIR, PROFILES_DIR, OUTPUT_DIR, WORDLISTS_DIR, RESOLVERS_DIR,
  DEFAULT_CONFIG, loadProfile, listProfiles, getConfig,
};
