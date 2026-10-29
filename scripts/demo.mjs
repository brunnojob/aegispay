import { randomBytes, randomUUID } from 'node:crypto';
import { signWebhook } from '../src/security.mjs';

const base = `http://127.0.0.1:${process.env.PORT ?? 8080}`;
async function request(path, options) {
  const response = await fetch(base + path, { ...options, signal: AbortSignal.timeout(5000) });
  const body = await response.json();
  if (!response.ok) throw new Error(`${response.status}: ${body.error}`);
  return body;
}
const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.DEMO_API_KEY}`, 'Idempotency-Key': randomUUID() };
const body = JSON.stringify({ amount: 4990, currency: 'BRL', payment_token: `pm_sandbox_${randomBytes(16).toString('hex')}` });
const created = await request('/v1/payments', { method: 'POST', headers, body });
const replay = await request('/v1/payments', { method: 'POST', headers, body });
const event = Buffer.from(JSON.stringify({ id: `evt_${randomUUID()}`, payment_id: created.payment.id, amount: 4990, currency: 'BRL', status: 'succeeded' }));
const timestamp = String(Math.floor(Date.now() / 1000));
await request('/v1/webhooks/sandbox', { method: 'POST', body: event, headers: {
  'Content-Type': 'application/json', 'X-Webhook-Timestamp': timestamp,
  'X-Webhook-Signature': signWebhook(Buffer.from(process.env.WEBHOOK_SECRET, 'hex'), event, timestamp)
} });
console.log(JSON.stringify({ created: created.payment, duplicate_prevented: replay.replay, confirmed: await request(`/v1/payments/${created.payment.id}`, { headers }) }, null, 2));
