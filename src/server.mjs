import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { digest, equal, validWebhook } from './security.mjs';
import { GatewayError, Store } from './store.mjs';

function requireShape(body, keys) {
  if (!body || typeof body !== 'object' || Array.isArray(body) ||
      Object.keys(body).length !== keys.length || keys.some(key => !Object.hasOwn(body, key))) {
    throw new GatewayError(400, 'invalid_fields');
  }
}
function paymentInput(body) {
  requireShape(body, ['amount', 'currency', 'payment_token']);
  if (!Number.isSafeInteger(body.amount) || body.amount < 1 || body.amount > 100_000_000 ||
      body.currency !== 'BRL' || typeof body.payment_token !== 'string' ||
      !/^pm_sandbox_[a-f0-9]{32}$/.test(body.payment_token)) throw new GatewayError(400, 'invalid_payment');
  return { amount: body.amount, currency: body.currency, payment_token: body.payment_token };
}
function eventInput(body) {
  requireShape(body, ['id', 'payment_id', 'amount', 'currency', 'status']);
  if (typeof body.id !== 'string' || !/^evt_[a-f0-9-]{36}$/.test(body.id) ||
      typeof body.payment_id !== 'string' || !/^pay_[a-f0-9-]{36}$/.test(body.payment_id) ||
      !Number.isSafeInteger(body.amount) || body.amount < 1 || body.currency !== 'BRL' ||
      !['succeeded', 'failed'].includes(body.status)) throw new GatewayError(400, 'invalid_event');
  return { id: body.id, payment_id: body.payment_id, amount: body.amount, currency: body.currency, status: body.status };
}
async function readBody(request) {
  if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') throw new GatewayError(415, 'json_required');
  const chunks = []; let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 8192) throw new GatewayError(413, 'body_too_large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
function parse(raw) {
  try { return JSON.parse(raw.toString('utf8')); }
  catch { throw new GatewayError(400, 'invalid_json'); }
}
export function loadConfig(env) {
  if (env.GATEWAY_MODE !== 'sandbox') throw new Error('GATEWAY_MODE must be sandbox');
  const names = ['DATA_KEY', 'AUDIT_KEY', 'WEBHOOK_SECRET'];
  for (const name of names) if (!/^[a-f0-9]{64}$/.test(env[name] ?? '')) throw new Error(`${name} must be 32 random bytes in hex`);
  if (new Set(names.map(name => env[name])).size !== names.length) throw new Error('Use independent secrets');
  const merchants = JSON.parse(env.MERCHANT_KEYS_JSON ?? '{}');
  const entries = Object.entries(merchants);
  if (!entries.length || entries.some(([id, hash]) => !/^[a-z0-9_-]{1,64}$/.test(id) || !/^[a-f0-9]{64}$/.test(hash))) throw new Error('Invalid merchant key hashes');
  if (new Set(entries.map(([, hash]) => hash)).size !== entries.length) throw new Error('Merchant keys must be unique');
  return { merchants, encryptionKey: Buffer.from(env.DATA_KEY, 'hex'), auditKey: Buffer.from(env.AUDIT_KEY, 'hex'), webhookSecret: Buffer.from(env.WEBHOOK_SECRET, 'hex') };
}
export function createGateway({ store, merchants, webhookSecret, rateLimit = 120, now = () => Date.now() }) {
  const buckets = new Map();
  function allow(identity) {
    const time = now();
    let bucket = buckets.get(identity);
    if (!bucket || bucket.until <= time) {
      if (buckets.size >= 10000) {
        for (const [key, value] of buckets) if (value.until <= time) buckets.delete(key);
        if (buckets.size >= 10000) throw new GatewayError(429, 'rate_limited');
      }
      bucket = { until: time + 60000, count: 0 }; buckets.set(identity, bucket);
    }
    if (++bucket.count > rateLimit) throw new GatewayError(429, 'rate_limited');
  }
  function authenticate(request) {
    const auth = request.headers.authorization ?? '';
    if (!/^Bearer [a-f0-9]{64}$/.test(auth)) throw new GatewayError(401, 'unauthorized');
    const hash = digest(auth.slice(7));
    let merchant;
    for (const [id, storedHash] of Object.entries(merchants)) if (equal(hash, storedHash)) merchant = id;
    if (!merchant) throw new GatewayError(401, 'unauthorized');
    return merchant;
  }
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 10000, headersTimeout: 10000 }, async (request, response) => {
    const requestId = randomUUID();
    const send = (status, data) => {
      response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
        'X-Request-Id': requestId, ...(status === 429 ? { 'Retry-After': '60' } : {}) });
      response.end(JSON.stringify(data));
    };
    try {
      allow(`ip:${request.socket.remoteAddress}`);
      const path = new URL(request.url, 'http://localhost').pathname;
      if (request.method === 'GET' && path === '/health') return send(200, { status: 'ok', mode: 'sandbox' });
      if (request.method === 'POST' && path === '/v1/webhooks/sandbox') {
        const raw = await readBody(request);
        if (!validWebhook(webhookSecret, raw, request.headers['x-webhook-timestamp'], request.headers['x-webhook-signature'], now())) throw new GatewayError(401, 'invalid_signature');
        const event = eventInput(parse(raw));
        return send(200, store.event(event, digest(JSON.stringify(event))));
      }
      const merchant = authenticate(request);
      allow(`merchant:${merchant}`);
      if (request.method === 'POST' && path === '/v1/payments') {
        const idem = request.headers['idempotency-key'];
        if (typeof idem !== 'string' || !/^[a-zA-Z0-9_-]{16,128}$/.test(idem)) throw new GatewayError(400, 'idempotency_key_required');
        const input = paymentInput(parse(await readBody(request)));
        const result = store.create(merchant, idem, digest(JSON.stringify(input)), input);
        return send(result.replay ? 200 : 201, result);
      }
      if (request.method === 'GET' && /^\/v1\/payments\/pay_[a-f0-9-]{36}$/.test(path)) return send(200, store.get(merchant, path.split('/').at(-1)));
      throw new GatewayError(404, 'not_found');
    } catch (error) {
      const known = error instanceof GatewayError;
      send(known ? error.status : 500, { error: known ? error.code : 'internal_error', request_id: requestId });
    }
  });
  server.maxRequestsPerSocket = 100;
  server.keepAliveTimeout = 5000;
  server.timeout = 15000;
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config = loadConfig(process.env);
  const dbPath = process.env.DATABASE_PATH ?? './data/gateway.db';
  mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 });
  process.umask(0o077);
  const store = new Store(dbPath, config.encryptionKey, config.auditKey);
  if (!store.verifyAudit()) throw new Error('Audit integrity check failed');
  const server = createGateway({ store, ...config });
  server.listen(Number(process.env.PORT ?? 8080), '127.0.0.1', () => console.log('AegisPay sandbox listening on localhost'));
  const shutdown = () => { server.close(() => { store.close(); process.exit(0); }); setTimeout(() => process.exit(1), 10000).unref(); };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}
