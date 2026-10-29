import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { mac, seal } from './security.mjs';

export class GatewayError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
export class Store {
  constructor(path, encryptionKey, auditKey) {
    this.key = encryptionKey;
    this.auditKey = auditKey;
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY, merchant TEXT NOT NULL, idem TEXT NOT NULL,
        fingerprint TEXT NOT NULL, payload TEXT NOT NULL, amount INTEGER NOT NULL,
        currency TEXT NOT NULL, status TEXT NOT NULL, created TEXT NOT NULL,
        UNIQUE(merchant, idem));
      CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS audit (
        seq INTEGER PRIMARY KEY, entry TEXT NOT NULL, previous TEXT NOT NULL, tag TEXT NOT NULL);`);
  }
  transaction(action) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = action(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  audit(action, merchant, payment) {
    const previous = this.db.prepare('SELECT tag FROM audit ORDER BY seq DESC LIMIT 1').get()?.tag ?? '0'.repeat(64);
    const entry = JSON.stringify({ action, merchant, payment, at: new Date().toISOString() });
    this.db.prepare('INSERT INTO audit(entry,previous,tag) VALUES(?,?,?)').run(entry, previous, mac(this.auditKey, previous + entry));
  }
  verifyAudit() {
    let previous = '0'.repeat(64);
    for (const row of this.db.prepare('SELECT * FROM audit ORDER BY seq').all()) {
      if (row.previous !== previous || row.tag !== mac(this.auditKey, previous + row.entry)) return false;
      previous = row.tag;
    }
    return true;
  }
  public(row) {
    return { id: row.id, amount: row.amount, currency: row.currency, status: row.status, created_at: row.created, mode: 'sandbox' };
  }
  create(merchant, idem, fingerprint, input) {
    return this.transaction(() => {
      const existing = this.db.prepare('SELECT * FROM payments WHERE merchant=? AND idem=?').get(merchant, idem);
      if (existing) {
        if (existing.fingerprint !== fingerprint) throw new GatewayError(409, 'idempotency_conflict');
        return { replay: true, payment: this.public(existing) };
      }
      const id = `pay_${randomUUID()}`;
      const created = new Date().toISOString();
      const payload = seal(this.key, { token: input.payment_token }, `${merchant}:${id}`);
      this.db.prepare('INSERT INTO payments VALUES(?,?,?,?,?,?,?,?,?)')
        .run(id, merchant, idem, fingerprint, payload, input.amount, input.currency, 'pending', created);
      this.audit('payment.created', merchant, id);
      return { replay: false, payment: this.get(merchant, id) };
    });
  }
  get(merchant, id) {
    const row = this.db.prepare('SELECT * FROM payments WHERE merchant=? AND id=?').get(merchant, id);
    if (!row) throw new GatewayError(404, 'payment_not_found');
    return this.public(row);
  }
  event(event, fingerprint) {
    return this.transaction(() => {
      const seen = this.db.prepare('SELECT fingerprint FROM events WHERE id=?').get(event.id);
      if (seen) {
        if (seen.fingerprint !== fingerprint) throw new GatewayError(409, 'event_conflict');
        return { received: true, duplicate: true };
      }
      const row = this.db.prepare('SELECT * FROM payments WHERE id=?').get(event.payment_id);
      if (!row) throw new GatewayError(404, 'payment_not_found');
      if (row.amount !== event.amount || row.currency !== event.currency) throw new GatewayError(409, 'payment_mismatch');
      if (row.status !== 'pending' && row.status !== event.status) throw new GatewayError(409, 'invalid_transition');
      this.db.prepare('UPDATE payments SET status=? WHERE id=?').run(event.status, event.payment_id);
      this.db.prepare('INSERT INTO events VALUES(?,?)').run(event.id, fingerprint);
      this.audit(`payment.${event.status}`, row.merchant, row.id);
      return { received: true, duplicate: false };
    });
  }
  close() { this.db.close(); }
}
