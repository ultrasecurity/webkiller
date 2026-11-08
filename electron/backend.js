const { spawn, execFile } = require('child_process');
const path = require('path');
const net = require('net');
const fs = require('fs');
const {
  getPythonPath,
  getToolsBinDir,
  getVenvDir,
  getVenvBinDir,
  getDataDir,
  getAppRoot,
} = require('./paths');

let proc = null;
let resolvedPort = null;

async function findFreePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

async function bootstrapVenv(onProgress) {
  const venvDir = getVenvDir();
  const pipBin = process.platform === 'win32'
    ? path.join(venvDir, 'Scripts', 'pip.exe')
    : path.join(venvDir, 'bin', 'pip');

  if (fs.existsSync(pipBin)) {
    if (onProgress) onProgress({ step: 'venv', status: 'exists' });
    return;
  }

  const systemPython = getPythonPath();
  if (!systemPython) {
    throw new Error('Python 3.10+ not found');
  }

  if (onProgress) onProgress({ step: 'venv', status: 'creating' });
  await execAsync(systemPython, ['-m', 'venv', venvDir]);

  if (onProgress) onProgress({ step: 'venv', status: 'installing-deps' });
  const reqFile = path.join(getAppRoot(), 'requirements.txt');
  await execAsync(pipBin, ['install', '-r', reqFile, '--quiet']);

  if (onProgress) onProgress({ step: 'venv', status: 'done' });
}

async function startBackend() {
  const port = await findFreePort();
  resolvedPort = port;

  const appPy = path.join(getAppRoot(), 'app.py');
  const venvPython = process.platform === 'win32'
    ? path.join(getVenvDir(), 'Scripts', 'python.exe')
    : path.join(getVenvDir(), 'bin', 'python3');

  const pythonExe = fs.existsSync(venvPython) ? venvPython : getPythonPath();
  if (!pythonExe) {
    throw new Error('Python not found');
  }

  const toolsBin = getToolsBinDir();
  const venvBin = getVenvBinDir();
  const sep = process.platform === 'win32' ? ';' : ':';
  const augmentedPath = [toolsBin, venvBin, process.env.PATH].join(sep);

  const env = {
    ...process.env,
    PATH: augmentedPath,
    WEBKILLER_PORT: String(port),
    WEBKILLER_OUTPUT_DIR: getDataDir(),
    WEBKILLER_DEBUG: 'false',
    PYTHONDONTWRITEBYTECODE: '1',
  };

  proc = spawn(pythonExe, [appPy], {
    cwd: getAppRoot(),
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  proc.stdout.on('data', (d) => {
    if (process.env.WEBKILLER_DEV) console.log('[flask]', d.toString().trim());
  });
  proc.stderr.on('data', (d) => {
    if (process.env.WEBKILLER_DEV) console.error('[flask]', d.toString().trim());
  });
  proc.on('exit', (code) => {
    if (process.env.WEBKILLER_DEV) console.log('[flask] exited', code);
    proc = null;
  });

  await waitForPort(port, 15000);
  return port;
}

async function waitForPort(port, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const sock = net.createConnection({ port, host: '127.0.0.1' }, () => {
          sock.destroy();
          resolve();
        });
        sock.on('error', reject);
      });
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error(`Flask backend did not start within ${timeoutMs}ms`);
}

function stopBackend() {
  if (proc) {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(proc.pid), '/f', '/t']);
    } else {
      proc.kill('SIGTERM');
    }
    setTimeout(() => {
      if (proc && !proc.killed) proc.kill('SIGKILL');
    }, 3000);
    proc = null;
  }
}

function getPort() {
  return resolvedPort;
}

function execAsync(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 300000, ...opts }, (err, stdout, stderr) => {
      if (err) reject(new Error(`${cmd} failed: ${stderr || err.message}`));
      else resolve(stdout);
    });
  });
}

module.exports = { bootstrapVenv, startBackend, stopBackend, getPort };
