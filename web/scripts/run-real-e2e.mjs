import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const webDirectory = path.resolve(scriptDirectory, '..');
const repositoryDirectory = path.resolve(webDirectory, '..');
const composeFile = path.join(repositoryDirectory, 'docker-compose.e2e.yml');
const playwrightCLI = path.join(webDirectory, 'node_modules', '@playwright', 'test', 'cli.js');

const runID = randomBytes(6).toString('hex');
const projectName = `nyauth-e2e-${runID}`;
const imageName = `nyauth-e2e:${runID}`;
const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'nyauth-real-e2e-'));
const secretDirectory = path.join(temporaryDirectory, 'secrets');
const abortController = new AbortController();
let interruptedSignal = '';
let imageBuilt = false;
let composeStarted = false;

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    interruptedSignal = signal;
    abortController.abort(new Error(`received ${signal}`));
  });
}

function secret(bytes = 24) {
  return randomBytes(bytes).toString('hex');
}

async function reserveLocalPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close();
        reject(new Error('could not reserve a local HTTP port'));
        return;
      }
      server.close((error) => error ? reject(error) : resolve(address.port));
    });
  });
}

function run(command, args, options = {}) {
  const {
    cwd = repositoryDirectory,
    env = process.env,
    signal = abortController.signal,
    allowFailure = false,
  } = options;

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: 'inherit', windowsHide: true });
    let settled = false;

    const abort = () => {
      if (!child.killed) child.kill('SIGTERM');
    };
    if (signal) {
      if (signal.aborted) abort();
      signal.addEventListener('abort', abort, { once: true });
    }

    child.once('error', (error) => {
      settled = true;
      signal?.removeEventListener('abort', abort);
      reject(error);
    });
    child.once('close', (code, childSignal) => {
      if (settled) return;
      signal?.removeEventListener('abort', abort);
      if (code === 0 || allowFailure) {
        resolve(code ?? 1);
        return;
      }
      reject(new Error(`${command} ${args.join(' ')} exited with ${childSignal || `code ${code}`}`));
    });
  });
}

function delay(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', abort);
      resolve();
    }, milliseconds);
    const abort = () => {
      clearTimeout(timer);
      reject(signal.reason || new Error('operation aborted'));
    };
    if (signal.aborted) {
      abort();
      return;
    }
    signal.addEventListener('abort', abort, { once: true });
  });
}

async function waitUntilReady(baseURL, signal) {
  const deadline = Date.now() + 120_000;
  let lastFailure = 'no response';
  while (Date.now() < deadline) {
    if (signal.aborted) throw signal.reason;
    try {
      const response = await fetch(`${baseURL}/readyz`, {
        cache: 'no-store',
        signal: AbortSignal.any([signal, AbortSignal.timeout(3_000)]),
      });
      if (response.ok) return;
      lastFailure = `HTTP ${response.status}`;
    } catch (error) {
      if (signal.aborted) throw signal.reason;
      lastFailure = error instanceof Error ? error.message : String(error);
    }
    await delay(1_000, signal);
  }
  throw new Error(`Nyauth did not become ready within 120 seconds (${lastFailure})`);
}

async function writeSecret(name, value) {
  await writeFile(path.join(secretDirectory, name), `${value}\n`, { mode: 0o600 });
}

let composeEnvironment;
let composeArguments;
let initialAdminPassword;
let changedAdminPassword;
const cleanupFailures = [];

async function compose(...args) {
  if (!composeEnvironment || !composeArguments) throw new Error('Compose environment is not initialized');
  return run('docker', [...composeArguments, ...args], { env: composeEnvironment });
}

async function bestEffort(command, args, options = {}) {
  try {
    await run(command, args, { ...options, signal: null, allowFailure: true });
  } catch (error) {
    console.error(`cleanup command could not start: ${error instanceof Error ? error.message : error}`);
  }
}

async function cleanupCommand(command, args, options = {}) {
  try {
    const code = await run(command, args, { ...options, signal: null, allowFailure: true });
    if (code !== 0) cleanupFailures.push(`${command} ${args.join(' ')} exited with code ${code}`);
  } catch (error) {
    cleanupFailures.push(error instanceof Error ? error.message : String(error));
  }
}

let primaryFailure;
try {
  const httpPort = await reserveLocalPort();
  const baseURL = `http://127.0.0.1:${httpPort}`;
  const migrationPassword = secret();
  const runtimePassword = secret();
  const redisPassword = secret();
  initialAdminPassword = `Initial-${secret(16)}-Aa1!`;
  changedAdminPassword = `Changed-${secret(16)}-Bb2!`;
  const masterKey = randomBytes(32).toString('base64');

  await mkdir(secretDirectory, { recursive: true, mode: 0o700 });
  await Promise.all([
    writeSecret('postgres_password', migrationPassword),
    writeSecret('database_runtime_password', runtimePassword),
    writeSecret('database_migration_dsn', `postgres://nyauth_migrator:${migrationPassword}@postgres:5432/nyauth?sslmode=disable`),
    writeSecret('database_runtime_dsn', `postgres://nyauth_runtime:${runtimePassword}@postgres:5432/nyauth?sslmode=disable`),
    writeSecret('redis_password', redisPassword),
    writeSecret('auth_master_key', masterKey),
    writeSecret('bootstrap_admin_password', initialAdminPassword),
  ]);

  composeEnvironment = {
    ...process.env,
    NYAUTH_E2E_BASE_URL: baseURL,
    NYAUTH_E2E_HTTP_PORT: String(httpPort),
    NYAUTH_E2E_IMAGE: imageName,
    NYAUTH_E2E_SECRET_DIR: secretDirectory.replaceAll('\\', '/'),
  };
  composeArguments = ['compose', '--ansi', 'never', '-p', projectName, '-f', composeFile];

  console.log(`[real-e2e] building isolated image ${imageName}`);
  await compose('build', 'nyauth');
  imageBuilt = true;

  console.log(`[real-e2e] starting isolated Compose project ${projectName} on ${baseURL}`);
  composeStarted = true;
  await compose('up', '-d');
  await waitUntilReady(baseURL, abortController.signal);

  console.log('[real-e2e] backend is ready; running Playwright smoke');
  await run(process.execPath, [playwrightCLI, 'test', '--config', 'playwright.real.config.ts'], {
    cwd: webDirectory,
    env: {
      ...process.env,
      NYAUTH_REAL_E2E_BASE_URL: baseURL,
      NYAUTH_REAL_E2E_INITIAL_PASSWORD: initialAdminPassword,
      NYAUTH_REAL_E2E_CHANGED_PASSWORD: changedAdminPassword,
    },
  });
} catch (error) {
  primaryFailure = error;
  if (composeStarted) {
    console.error('[real-e2e] failure diagnostics follow');
    await bestEffort('docker', [...composeArguments, 'ps', '-a'], { env: composeEnvironment });
    await bestEffort('docker', [...composeArguments, 'logs', '--no-color', '--tail', '200', 'migrate', 'nyauth'], { env: composeEnvironment });
  }
} finally {
  console.log(`[real-e2e] cleaning isolated Compose project ${projectName}`);
  if (composeStarted) {
    await cleanupCommand('docker', [...composeArguments, 'down', '-v', '--remove-orphans', '--timeout', '10'], { env: composeEnvironment });
  }
  if (imageBuilt) {
    await cleanupCommand('docker', ['image', 'rm', imageName]);
  }
  try {
    await rm(temporaryDirectory, { recursive: true, force: true });
  } catch (error) {
    cleanupFailures.push(`temporary directory cleanup failed: ${error instanceof Error ? error.message : error}`);
  }
}

if (cleanupFailures.length > 0) {
  const cleanupError = new Error(`cleanup was incomplete:\n- ${cleanupFailures.join('\n- ')}`);
  if (primaryFailure) {
    console.error(`[real-e2e] ${cleanupError.message}`);
  } else {
    primaryFailure = cleanupError;
  }
}

if (primaryFailure) {
  console.error(`[real-e2e] ${primaryFailure instanceof Error ? primaryFailure.message : primaryFailure}`);
  process.exitCode = 1;
} else if (interruptedSignal) {
  console.error(`[real-e2e] interrupted by ${interruptedSignal}`);
  process.exitCode = 1;
} else {
  console.log('[real-e2e] smoke completed and all isolated resources were removed');
}
