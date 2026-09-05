import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import https from 'node:https';
import { resolve } from 'node:path';
import { promisify } from 'node:util';

const exec = promisify(execFile);
assert.equal(process.argv.length, 3, 'usage: node smoke-binary.mjs <vt binary>');
const binary = resolve(process.argv[2]);
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
  !key.startsWith('VT_') && !/^(https?|all|no)_proxy$/i.test(key)));
Object.assign(env, { VT_CONFIG: '/dev/null', VT_AUTH: '', RUST_LOG: 'error' });
const options = { env, timeout: 15_000, maxBuffer: 1024 * 1024 };

assert.match((await exec(binary, ['version'], options)).stdout, /^vt /);
assert.match((await exec(binary, ['--help'], options)).stdout, /Usage:/);

// An ephemeral, untrusted certificate exercises rustls/ring and certificate
// rejection without public network access or a test-only trust bypass in VT.
// Both the disposable key and certificate stay in memory, never in a file.
const { privateKey: key } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
// Node's child stdin is a socket on Unix; the pipe lets OpenSSL reopen
// /dev/stdin as a file without putting the test key on disk.
const certificate = exec('sh', ['-c',
  'cat | openssl req -x509 -new -key /dev/stdin -days 1 -config /dev/null '
  + '-subj /CN=localhost -addext subjectAltName=IP:127.0.0.1',
], options);
certificate.child.stdin.end(key);
const { stdout: cert } = await certificate;
const tlsErrors = [];
const server = https.createServer({ key, cert, handshakeTimeout: 5_000 }, (_req, res) => {
  res.writeHead(200);
  res.end('unexpected trusted connection');
});
server.on('tlsClientError', (error, socket) => {
  tlsErrors.push(error.message);
  socket.destroy();
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
try {
  const url = `https://127.0.0.1:${server.address().port}`;
  const { stdout } = await exec(binary, ['doctor'], {
    ...options,
    env: { ...env, VT_BACKEND: 'passkey', VT_PASSKEY_URL: url },
  });
  // doctor deliberately exits zero even on failed probes; inspect its report
  // AND the server's TLS alert so a skipped/failed connection cannot pass.
  assert.ok(stdout.includes(`${url} unreachable:`), stdout);
  assert.ok(tlsErrors.some(message => /unknown ca|certificate unknown|bad certificate/i.test(message)),
    `expected an untrusted-certificate TLS alert, got: ${JSON.stringify(tlsErrors)}`);
} finally {
  server.closeAllConnections();
  await new Promise((resolveClose, reject) => server.close(error => error ? reject(error) : resolveClose()));
}
console.log('binary smoke passed: version, help, local TLS certificate rejection');
