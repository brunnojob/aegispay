# AegisPay

A security-focused payment gateway sandbox by [brunnodev.store](https://brunnodev.store).

Create payment intents, prevent duplicate requests, encrypt sandbox tokens, and confirm payment status through signed events. Built with Node.js 24 and SQLite, without third-party runtime dependencies.

**Current status:** local sandbox. No money movement, bank connectivity, card tokenization service, Pix QR generation, or live processor adapter. Sandbox tokens are random test identifiers, not real payment credentials. This project is not certified or approved for production payments.

## Run

Requires Node.js 24.15 or newer in the 24.x series. Run commands from the project directory:

```sh
npm run setup
npm test
npm start
```

In another terminal:

```sh
npm run demo
```

The demo creates a BRL 49.90 sandbox intent, repeats its request without creating another payment, and sends a signed simulated confirmation. The API listens only on `127.0.0.1:8080`.

Setup generates independent random secrets and writes `.env` with owner-only permissions where supported. It refuses to overwrite an existing file. Never commit `.env` or the database. `DEMO_API_KEY` is only for the local demonstration; the server authenticates against merchant key hashes in `MERCHANT_KEYS_JSON`.

## Implemented controls

| Area | Behavior |
| --- | --- |
| Authentication | Random bearer API keys, SHA-256 hashes in the server merchant registry, constant-time hash comparison |
| Authorization | Merchant-scoped payment reads and idempotency keys |
| Stored tokens | AES-256-GCM, random 96-bit IV, authenticated merchant and payment context |
| Duplicate requests | SQLite transaction and merchant/key uniqueness; changed payload returns HTTP 409 |
| Confirmations | HMAC-SHA-256 over timestamp and raw body; five-minute time window; persistent event deduplication |
| Payment state | Positive integer amounts in centavos, BRL only, pending to succeeded/failed; terminal states cannot be reversed |
| Event consistency | Payment ID, amount and currency must match before status update |
| Audit | HMAC chain for payment state changes; checked on startup; no raw token in entries |
| API boundaries | Strict request fields, 8 KiB body limit, bounded process-local rate limiter, request timeouts |

API responses and audit entries exclude payment tokens. Amounts, status, merchant IDs and timestamps remain plaintext operational metadata. Encryption protects tokens, not the entire database or a compromised running process.

## API

All payment endpoints require `Authorization: Bearer <merchant-key>`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/health` | Local service health and sandbox mode |
| POST | `/v1/payments` | Create or replay an intent; requires `Idempotency-Key` with 16–128 letters, digits, `_` or `-` |
| GET | `/v1/payments/{id}` | Read a payment belonging to the authenticated merchant |
| POST | `/v1/webhooks/sandbox` | Apply a simulated processor event authenticated by its independent signing secret |

Payment body:

```json
{
  "amount": 4990,
  "currency": "BRL",
  "payment_token": "pm_sandbox_0123456789abcdef0123456789abcdef"
}
```

Extra fields are rejected. Never send card numbers, CVV, customer names, CPF or banking credentials. The API intentionally accepts only synthetic tokens in this phase.

Webhook body:

```json
{
  "id": "evt_00000000-0000-4000-8000-000000000000",
  "payment_id": "pay_00000000-0000-4000-8000-000000000000",
  "amount": 4990,
  "currency": "BRL",
  "status": "succeeded"
}
```

Headers: `X-Webhook-Timestamp` is Unix time in seconds; `X-Webhook-Signature` is the hexadecimal HMAC of `timestamp + "." + rawBody`, using the hex-decoded webhook secret. This is the project's sandbox protocol; real providers have their own verification schemes. Merchant keys do not authorize confirmations.

## Next implementation stages

1. Choose a processor and implement hosted checkout/tokenization and official webhook verification in test mode.
2. Add Pix creation, expiration and reconciliation through that processor's documented API.
3. Introduce PostgreSQL, transactional outbox, retry/reconciliation workers and scoped/rotatable merchant credentials.
4. Introduce managed keys and key versions, a distributed rate limiter, operator access controls, monitoring and external audit checkpoints.
5. Conduct independent security review, processor onboarding and the applicable compliance assessment before live use.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md) and [Portuguese project brief](docs/projeto.pt-BR.md). See [SECURITY.md](SECURITY.md) for limitations and reporting.

MIT License. Copyright 2026 brunnodev.store.
