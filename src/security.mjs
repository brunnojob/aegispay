import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const digest = value => createHash('sha256').update(value).digest('hex');
export const mac = (key, value) => createHmac('sha256', key).update(value).digest('hex');
export function equal(a, b) {
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
export function seal(key, value, context) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
  return JSON.stringify({ v: 1, iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), data: ciphertext.toString('hex') });
}
export function open(key, envelope, context) {
  const box = JSON.parse(envelope);
  if (box.v !== 1) throw new Error('Unsupported envelope');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'hex'));
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(Buffer.from(box.tag, 'hex'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(box.data, 'hex')), decipher.final()]));
}
export function signWebhook(secret, raw, timestamp) {
  return mac(secret, Buffer.concat([Buffer.from(`${timestamp}.`), raw]));
}
export function validWebhook(secret, raw, timestamp, signature, now = Date.now()) {
  if (!/^\d{10}$/.test(timestamp ?? '') || !/^[a-f0-9]{64}$/.test(signature ?? '')) return false;
  if (Math.abs(Math.floor(now / 1000) - Number(timestamp)) > 300) return false;
  return equal(signWebhook(secret, raw, timestamp), signature);
}
