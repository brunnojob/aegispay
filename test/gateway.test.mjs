import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createGateway, loadConfig } from '../src/server.mjs';
import { Store } from '../src/store.mjs';
import { digest, open, seal, signWebhook } from '../src/security.mjs';

const token = () => `pm_sandbox_${randomBytes(16).toString('hex')}`;
async function fixture(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'aegispay-'));
  const key = randomBytes(32), auditKey = randomBytes(32), webhookSecret = randomBytes(32);
  const a = randomBytes(32).toString('hex'), b = randomBytes(32).toString('hex');
  const store = new Store(join(directory, 'test.db'), key, auditKey);
  const server = createGateway({ store, merchants: { a: digest(a), b: digest(b) }, webhookSecret, ...options });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => { server.close(resolve); server.closeIdleConnections(); }); store.close(); rmSync(directory, { recursive: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const req = async (path, { key: apiKey = a, body, headers = {}, method = body === undefined ? 'GET' : 'POST' } = {}) => {
    const response = await fetch(base + path, { method, headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  const input = { amount: 4990, currency: 'BRL', payment_token: token() };
  const create = (body = input, idem = randomUUID(), apiKey = a) => req('/v1/payments', { key: apiKey, body, headers: { 'Idempotency-Key': idem } });
  const webhook = (body, timestamp = String(Math.floor(Date.now() / 1000)), signature) => {
    const raw = JSON.stringify(body);
    return req('/v1/webhooks/sandbox', { body: raw, headers: { 'X-Webhook-Timestamp': timestamp, 'X-Webhook-Signature': signature ?? signWebhook(webhookSecret, Buffer.from(raw), timestamp) } });
  };
  return { req, create, input, store, key, a, b, webhook };
}
const event = payment => ({ id: `evt_${randomUUID()}`, payment_id: payment.id, amount: payment.amount, currency: payment.currency, status: 'succeeded' });

test('authentication and health response', async t => {
  const f = await fixture(t);
  assert.equal((await f.req('/health', { key: '' })).status, 200);
  assert.equal((await f.req('/v1/payments', { key: '' })).status, 401);
  assert.equal((await f.req('/v1/payments', { key: '0'.repeat(64) })).status, 401);
});
test('duplicate concurrent requests create exactly one payment', async t => {
  const f = await fixture(t), idem = randomUUID();
  const responses = await Promise.all(Array.from({ length: 12 }, () => f.create(f.input, idem)));
  assert.equal(responses.filter(r => r.status === 201).length, 1);
  assert.equal(new Set(responses.map(r => r.body.payment.id)).size, 1);
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM payments').get().n, 1);
  assert.equal((await f.create({ ...f.input, amount: 100 }, idem)).status, 409);
});
test('merchant isolation also scopes idempotency', async t => {
  const f = await fixture(t), idem = randomUUID();
  const created = await f.create(f.input, idem);
  assert.equal((await f.req(`/v1/payments/${created.body.payment.id}`, { key: f.b })).status, 404);
  const other = await f.create(f.input, idem, f.b);
  assert.equal(other.status, 201);
  assert.notEqual(other.body.payment.id, created.body.payment.id);
});
test('payment validation rejects extra card fields and invalid money', async t => {
  const f = await fixture(t);
  for (const body of [{ ...f.input, cvv: '123' }, { ...f.input, amount: 1.5 }, { ...f.input, amount: -1 }, { ...f.input, amount: 100_000_001 }, { ...f.input, currency: 'USD' }, { ...f.input, payment_token: '4242424242424242' }, null, []]) {
    assert.equal((await f.create(body)).status, 400);
  }
  assert.equal((await f.req('/v1/payments', { body: f.input })).status, 400);
  assert.equal((await f.create('{bad')).status, 400);
});
test('token is encrypted and omitted from API and audit', async t => {
  const f = await fixture(t), created = await f.create();
  const row = f.store.db.prepare('SELECT * FROM payments').get();
  assert.ok(!JSON.stringify(row).includes(f.input.payment_token));
  assert.ok(!JSON.stringify(created).includes(f.input.payment_token));
  assert.equal(open(f.key, row.payload, `a:${row.id}`).token, f.input.payment_token);
  assert.throws(() => open(f.key, row.payload, `b:${row.id}`));
  assert.ok(!JSON.stringify(f.store.db.prepare('SELECT * FROM audit').all()).includes(f.input.payment_token));
});
test('encryption rejects altered ciphertext and wrong keys', () => {
  const key = randomBytes(32), envelope = seal(key, { token: 'sample' }, 'context');
  const changed = JSON.parse(envelope);
  changed.tag = '0'.repeat(32);
  assert.throws(() => open(key, JSON.stringify(changed), 'context'));
  assert.throws(() => open(randomBytes(32), envelope, 'context'));
  assert.notEqual(envelope, seal(key, { token: 'sample' }, 'context'));
});
test('valid signed event confirms once and rejects changed event ID reuse', async t => {
  const f = await fixture(t), created = await f.create(), notification = event(created.body.payment);
  assert.equal((await f.webhook(notification)).status, 200);
  assert.equal((await f.webhook(notification)).body.duplicate, true);
  assert.equal((await f.webhook({ ...notification, status: 'failed' })).status, 409);
  assert.equal((await f.req(`/v1/payments/${notification.payment_id}`)).body.status, 'succeeded');
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 2);
});
test('invalid, expired, future signatures cannot change payment status', async t => {
  const f = await fixture(t), created = await f.create(), notification = event(created.body.payment);
  assert.equal((await f.webhook(notification, undefined, '0'.repeat(64))).status, 401);
  for (const offset of [-301, 301]) assert.equal((await f.webhook(notification, String(Math.floor(Date.now() / 1000) + offset))).status, 401);
  assert.equal((await f.req(`/v1/payments/${notification.payment_id}`)).body.status, 'pending');
});
test('event amount, currency and transitions are enforced atomically', async t => {
  const f = await fixture(t), created = await f.create(), notification = event(created.body.payment);
  assert.equal((await f.webhook({ ...notification, amount: 5000 })).status, 409);
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM events').get().n, 0);
  assert.equal((await f.webhook({ ...notification, currency: 'USD' })).status, 400);
  assert.equal((await f.webhook(notification)).status, 200);
  assert.equal((await f.webhook({ ...notification, id: `evt_${randomUUID()}`, status: 'failed' })).status, 409);
});
test('unknown payment event can be retried and does not consume event ID', async t => {
  const f = await fixture(t);
  assert.equal((await f.webhook({ id: `evt_${randomUUID()}`, payment_id: `pay_${randomUUID()}`, amount: 1, currency: 'BRL', status: 'succeeded' })).status, 404);
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM events').get().n, 0);
});
test('audit detects edited historical entries', async t => {
  const f = await fixture(t); await f.create();
  assert.equal(f.store.verifyAudit(), true);
  f.store.db.prepare('UPDATE audit SET entry=? WHERE seq=1').run('{}');
  assert.equal(f.store.verifyAudit(), false);
});
test('transaction rollback removes payment if audit fails', async t => {
  const f = await fixture(t);
  f.store.audit = () => { throw new Error('storage failure'); };
  assert.equal((await f.create()).status, 500);
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM payments').get().n, 0);
});
test('rate limit bounds requests', async t => {
  const f = await fixture(t, { rateLimit: 2 });
  assert.equal((await f.req('/health')).status, 200);
  assert.equal((await f.req('/health')).status, 200);
  assert.equal((await f.req('/health')).status, 429);
});
test('body limit rejects oversized requests', async t => {
  const f = await fixture(t);
  assert.equal((await f.create({ ...f.input, extra: 'x'.repeat(9000) })).status, 413);
});
test('payment and idempotency survive database reopen', () => {
  const directory = mkdtempSync(join(tmpdir(), 'aegispay-restart-'));
  const path = join(directory, 'gateway.db'), key = randomBytes(32), auditKey = randomBytes(32);
  const input = { amount: 100, currency: 'BRL', payment_token: token() };
  let store;
  try {
    store = new Store(path, key, auditKey);
    const first = store.create('a', 'same-key', digest(JSON.stringify(input)), input);
    store.close();
    store = new Store(path, key, auditKey);
    assert.equal(store.verifyAudit(), true);
    const replay = store.create('a', 'same-key', digest(JSON.stringify(input)), input);
    assert.equal(replay.replay, true);
    assert.equal(replay.payment.id, first.payment.id);
  } finally { store?.close(); rmSync(directory, { recursive: true }); }
});
test('configuration fails closed for live mode, missing and reused secrets', () => {
  assert.throws(() => loadConfig({ GATEWAY_MODE: 'live' }));
  assert.throws(() => loadConfig({ GATEWAY_MODE: 'sandbox' }));
  const env = { GATEWAY_MODE: 'sandbox', DATA_KEY: 'a'.repeat(64), AUDIT_KEY: 'b'.repeat(64), WEBHOOK_SECRET: 'c'.repeat(64), MERCHANT_KEYS_JSON: JSON.stringify({ a: 'd'.repeat(64) }) };
  assert.ok(loadConfig(env));
  assert.throws(() => loadConfig({ ...env, AUDIT_KEY: env.DATA_KEY }));
});
