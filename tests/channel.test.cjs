const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { execFileSync } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');
const { WebSocketServer } = require('ws');
const { SecureChannelClient, bindSecureChannelServer } = require('../dist');
let directory, ca, key, cert;
before(() => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-channel-'));
  const run = (...args) => execFileSync('openssl', args, { cwd: directory, stdio: 'ignore' });
  run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=Test CA');
  run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'peer.key', '-out', 'peer.csr', '-subj', '/CN=localhost');
  fs.writeFileSync(path.join(directory, 'extensions'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n');
  run('x509', '-req', '-in', 'peer.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'peer.pem', '-days', '1', '-extfile', 'extensions');
  ca = fs.readFileSync(path.join(directory, 'ca.pem'), 'utf8');
  key = fs.readFileSync(path.join(directory, 'peer.key'), 'utf8');
  cert = fs.readFileSync(path.join(directory, 'peer.pem'), 'utf8');
});
after(() => fs.rmSync(directory, { recursive: true, force: true }));
async function fixture(t, overrides = {}) {
  const server = https.createServer({ key, cert, ca, requestCert: true, rejectUnauthorized: true });
  const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 });
  bindSecureChannelServer({ wss, onRequest: async (_route, payload) => payload, ...overrides });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const client = new SecureChannelClient({ url: `wss://127.0.0.1:${server.address().port}`, serviceId: 'test', certificate: cert, privateKey: key, caCertificate: ca, reconnectDelayMs: 20, requestTimeoutMs: 500 });
  t.after(async () => {
    client.disconnect();
    for (const socket of wss.clients) socket.terminate();
    await new Promise(resolve => wss.close(resolve));
    await new Promise(resolve => server.close(resolve));
  });
  return { client, wss, server };
}
test('mTLS requests preserve generated replay headers', async t => {
  const { client } = await fixture(t, { onRequest: async (_route, payload, message) => ({ payload, nonce: message.headers['x-sc-nonce'] }) });
  await Promise.all([client.connect(), client.connect()]);
  const response = await client.request({ route: 'echo', payload: 'hello', headers: { 'x-sc-ts': '0', 'x-sc-nonce': 'override' } });
  assert.equal(response.payload, 'hello');
  assert.notEqual(response.nonce, 'override');
});
test('disconnect does not reconnect', async t => {
  const { client, wss } = await fixture(t);
  let connections = 0;
  wss.on('connection', () => connections++);
  await client.connect();
  client.disconnect();
  await delay(100);
  assert.equal(connections, 1);
});
test('transport closure rejects pending requests', async t => {
  const { client } = await fixture(t, { onRequest: async (_route, _payload, _message, socket) => { socket.close(); return null; } });
  await client.connect();
  await assert.rejects(client.request({ route: 'close' }), /disconnect|closed/i);
});
test('untrusted TLS certificate is rejected without explicit CA', async t => {
  const { server } = await fixture(t);
  const client = new SecureChannelClient({ url: `wss://127.0.0.1:${server.address().port}`, serviceId: 'test', certificate: cert, privateKey: key, reconnectDelayMs: 1000 });
  t.after(() => client.disconnect());
  await assert.rejects(client.connect(), /certificate|issuer|verify/i);
});
test('plaintext transport is rejected', async () => {
  const client = new SecureChannelClient({ url: 'ws://localhost', serviceId: 'test', certificate: cert, privateKey: key });
  await assert.rejects(client.connect(), /requires.*wss/);
});
test('invalid replay protection settings are rejected', () => {
  const wss = new WebSocketServer({ noServer: true });
  assert.throws(() => bindSecureChannelServer({ wss, onRequest: async () => null, maxSkewMs: 100, nonceTtlMs: 99 }), /replay/);
  wss.close();
});
test('certificate authorization callback fails closed', async t => {
  const { client } = await fixture(t, { verifyClient: () => { throw new Error('private policy failure'); } });
  await client.connect();
  await assert.rejects(client.request({ route: 'echo' }), /disconnect|closed/i);
});
test('repeated nonce is not dispatched twice', async t => {
  const { WebSocket } = require('ws');
  let calls = 0;
  const { server } = await fixture(t, { onRequest: async () => ++calls });
  const socket = new WebSocket(`wss://127.0.0.1:${server.address().port}`, { key, cert, ca });
  t.after(() => socket.terminate());
  await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
  const message = { type: 'request', id: 'first', route: 'echo', headers: { 'x-sc-ts': String(Date.now()), 'x-sc-nonce': 'same-nonce' } };
  const response = new Promise(resolve => socket.once('message', resolve));
  socket.send(JSON.stringify(message));
  await response;
  socket.send(JSON.stringify({ ...message, id: 'second' }));
  await delay(50);
  assert.equal(calls, 1);
});
