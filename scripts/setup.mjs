import { writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { digest } from '../src/security.mjs';

const secret = () => randomBytes(32).toString('hex');
const merchantKey = secret();
const values = {
  GATEWAY_MODE: 'sandbox', DATA_KEY: secret(), AUDIT_KEY: secret(), WEBHOOK_SECRET: secret(),
  MERCHANT_KEYS_JSON: JSON.stringify({ demo: digest(merchantKey) }), DEMO_API_KEY: merchantKey,
  DATABASE_PATH: './data/gateway.db', PORT: '8080'
};
writeFileSync('.env', Object.entries(values).map(([key, value]) => `${key}='${value}'`).join('\n') + '\n', { flag: 'wx', mode: 0o600 });
console.log('Created .env with random sandbox secrets. Existing configurations are never overwritten.');
