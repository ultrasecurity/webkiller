const { execFile } = require('child_process');

async function checkPython() {
  const candidates = process.platform === 'win32'
    ? ['python3', 'python', 'py']
    : ['python3', 'python'];

  for (const cmd of candidates) {
    try {
      const result = await new Promise((resolve, reject) => {
        execFile(cmd, ['--version'], { timeout: 5000 }, (err, stdout, stderr) => {
          if (err) reject(err);
          else resolve((stdout || stderr).trim());
        });
      });
      const match = result.match(/Python (\d+)\.(\d+)\.(\d+)/);
      if (match) {
        const [, major, minor, patch] = match.map(Number);
        const version = `${major}.${minor}.${patch}`;
        const meetsMinimum = major === 3 && minor >= 10;
        const fullPath = await whichCmd(cmd);
        return { found: true, path: fullPath, version, meetsMinimum };
      }
    } catch {}
  }
  return { found: false, path: null, version: null, meetsMinimum: false };
}

function whichCmd(cmd) {
  return new Promise((resolve) => {
    const { execFile: ef } = require('child_process');
    const whichBin = process.platform === 'win32' ? 'where' : 'which';
    ef(whichBin, [cmd], { timeout: 3000 }, (err, stdout) => {
      if (err) resolve(cmd);
      else resolve(stdout.trim().split('\n')[0]);
    });
  });
}

module.exports = { checkPython };
