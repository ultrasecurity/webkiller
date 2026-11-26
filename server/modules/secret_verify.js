const { BaseModule, ModuleResult } = require('./base');
const { runTool, batchAsync } = require('../runner');
const { isInstalled } = require('../registry');

class SecretVerify extends BaseModule {
  static moduleName = 'secret_verify';
  static phase = 'P6b';
  static toolsNeeded = ['trufflehog'];

  async execute() {
    const findings = this.workspace.readJsonl('findings.jsonl');
    const jsFindings = findings.filter(f => f.type === 'js_secret');
    const urls = this.workspace.readLines('urls.txt');
    const jsUrls = urls.filter(u => {
      const lower = u.toLowerCase();
      return lower.endsWith('.js') || lower.endsWith('.mjs');
    });

    let allVerified = [];
    const toolUsed = [];
    let fallback = false;

    if (isInstalled('trufflehog') && jsUrls.length > 0) {
      toolUsed.push('trufflehog');
      this.emit('log', { msg: `trufflehog: scanning ${jsUrls.length} JS files` });
      const truffleResults = await this._runTrufflehog(jsUrls);
      allVerified.push(...truffleResults);
    }

    if (jsFindings.length > 0) {
      toolUsed.push('python-verify');
      this.emit('log', { msg: `Verifying ${jsFindings.length} secret candidates` });
      const verified = await this._verifySecrets(jsFindings);
      allVerified.push(...verified);
      if (!isInstalled('trufflehog')) {
        fallback = true;
      }
    }

    if (jsFindings.length === 0 && jsUrls.length === 0) {
      return new ModuleResult({ module: SecretVerify.moduleName, status: 'skipped', errors: ['No secrets to verify'] });
    }

    if (allVerified.length > 0) {
      this.workspace.appendJsonl('confirmed.jsonl', allVerified);
      const findingsRecords = allVerified.map(v => ({ ...v, type: 'dast_confirmed' }));
      this.workspace.appendJsonl('findings.jsonl', findingsRecords);
    }

    return new ModuleResult({
      module: SecretVerify.moduleName,
      items: allVerified.map(v => v.url || ''),
      records: allVerified,
      toolUsed: toolUsed.join(', ') || 'none',
      fallback,
    });
  }

  async _runTrufflehog(jsUrls) {
    const targets = jsUrls.slice(0, 20);
    this.emit('log', { msg: `trufflehog: ${targets.length} files (5 concurrent)` });
    return batchAsync(targets, 5, async (url) => {
      const result = await runTool(
        `trufflehog filesystem --json --no-update "${url}"`,
        60,
      );
      if (result.returncode !== 0 || !result.stdout.trim()) return null;
      const items = [];
      for (const line of result.stdout.split('\n')) {
        if (!line.trim()) continue;
        try {
          const data = JSON.parse(line);
          items.push({
            name: `Verified Secret: ${data.DetectorName || 'unknown'}`,
            severity: 'critical',
            url,
            evidence: {
              detector: data.DetectorName || '',
              verified: data.Verified || false,
              raw: (data.Raw || '').slice(0, 40),
            },
            type: 'dast_confirmed',
            vuln_class: 'secret_exposure',
            module: SecretVerify.moduleName,
          });
        } catch { /* skip */ }
      }
      return items.length ? items : null;
    }).then(results => results.flat());
  }

  async _verifySecrets(findings) {
    const verified = [];
    for (const finding of findings) {
      const evidence = finding.evidence || {};
      const patternType = evidence.pattern || '';
      const matchValue = evidence.match || '';
      if (!matchValue) continue;

      let isValid = false;
      if (patternType === 'aws_key') {
        isValid = this._checkAws(matchValue);
      } else if (patternType === 'google_api') {
        isValid = await this._checkGoogleApi(matchValue);
      } else if (patternType === 'github_token') {
        isValid = await this._checkGithubToken(matchValue);
      } else if (patternType === 'slack_token') {
        isValid = await this._checkSlackToken(matchValue);
      } else if (patternType === 'jwt' || patternType === 'bearer_token') {
        isValid = true;
      }

      if (isValid) {
        verified.push({
          name: `Verified: ${patternType}`,
          severity: 'critical',
          url: finding.url || '',
          evidence: {
            pattern: patternType,
            verified: true,
            snippet: matchValue.slice(0, 30) + '...',
          },
          type: 'dast_confirmed',
          vuln_class: 'secret_exposure',
          module: SecretVerify.moduleName,
        });
      }
    }
    return verified;
  }

  _checkAws(key) {
    return /^(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}$/.test(key);
  }

  async _checkGoogleApi(key) {
    try {
      const resp = await fetch(
        `https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key=${key}`,
        { signal: AbortSignal.timeout(5000) },
      );
      return resp.status !== 403;
    } catch {
      return false;
    }
  }

  async _checkGithubToken(token) {
    try {
      const resp = await fetch('https://api.github.com/user', {
        headers: { Authorization: `token ${token}` },
        signal: AbortSignal.timeout(5000),
      });
      return resp.status === 200;
    } catch {
      return false;
    }
  }

  async _checkSlackToken(token) {
    try {
      const resp = await fetch('https://slack.com/api/auth.test', {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(5000),
      });
      const data = await resp.json();
      return data.ok === true;
    } catch {
      return false;
    }
  }
}

module.exports = SecretVerify;
