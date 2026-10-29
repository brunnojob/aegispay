# Architecture

## Current implementation

The merchant backend submits a synthetic token and a BRL amount to the local HTTP API. Authentication resolves one merchant identity. A SQLite immediate transaction either returns the existing intent or writes a pending intent and its audit entry. The encrypted token is bound to the merchant/payment pair using AES-GCM additional authenticated data.

The sandbox event sender uses an independent secret. Its signature covers the raw body and timestamp. After verification, one database transaction validates the payment amount/currency/state, records the event ID, updates status and appends audit evidence. An event retry is acknowledged without repeating the update; an altered event under the same ID is rejected.

Payment creation never claims that payment has occurred. Only an authenticated sandbox event changes the state. This version has no outgoing network payment call, so its local transaction does not solve processor/database atomicity for a future live adapter.

## Trust boundaries

| Boundary | Current protection | Remaining work |
| --- | --- | --- |
| Merchant to API | Bearer authentication and merchant ownership checks; localhost listener | HTTPS termination, credential issuance/scopes/rotation, distributed limits |
| API to database | Parameterized statements and transactions | Dedicated service identity, encrypted backups, production database operations |
| Stored token to key | AES-GCM using independent environment key | Managed KMS/HSM, versioned envelopes, rotation and recovery |
| Processor to API | Custom sandbox HMAC and event deduplication | Official provider verification and authoritative reconciliation |
| Operator to service | Host access controls only | MFA, role separation, privileged-action audit |

## Production design targets

Use a hosted checkout or provider-controlled payment fields so raw card data goes directly to the selected processor. Add a provider adapter with create/query/refund operations and a stable upstream idempotency key derived from the gateway payment ID. Persist an intent and an outbox job before dispatch; retry unknown outcomes using the same provider key, and reconcile against the provider API. Never create a second charge merely because the first call timed out.

Use PostgreSQL transactions and unique constraints for shared state; workers must deduplicate jobs. Handle asynchronous authentication, expiration, cancellation, refunds and disputes as explicit state transitions. Multiple providers require separate secrets, event namespaces and token ownership rules. The MVP has one sandbox provider namespace.

Amounts must come from the merchant's trusted backend order data. The gateway does not validate product pricing or inventory. Tokenization and encryption do not hide transactions from banks/processors or establish regulatory compliance by themselves.

## Cryptography references

- [Node.js crypto](https://nodejs.org/docs/latest-v24.x/api/crypto.html): authenticated encryption, HMAC, secure randomness and comparison.
- [PCI SSC: CVV retention](https://www.pcisecuritystandards.org/faqs/1280/): CVV cannot be stored after authorization.
- [Stripe webhook signatures](https://docs.stripe.com/webhooks/signature): example provider-specific signature verification using the raw body. Stripe is a candidate integration, not an implemented dependency or selected account.

No custom cipher or cryptographic primitive is implemented. The project defines only application-level envelope and sandbox message formats around standard primitives.
