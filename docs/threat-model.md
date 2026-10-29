# Threat model

Assets: merchant credentials, payment tokens, payment state and audit history. Assumed attackers can submit arbitrary HTTP requests and obtain a copy of the database, but initially do not control the host or its secrets.

| Threat | Implemented mitigation | Residual risk |
| --- | --- | --- |
| Cross-merchant access | Merchant ID originates from API key; ownership in read query | Stolen merchant key grants its account access |
| Duplicate intent creation | Durable merchant/key uniqueness and immediate transaction | Caller must retain and reuse its idempotency key |
| Forged confirmation | Independent HMAC secret and raw-body validation | Compromised signing secret can forge events |
| Event replay | Persistent unique event ID and timestamp window | Event records currently have no cleanup policy |
| Changed price in confirmation | Exact amount and currency comparison | Merchant backend must validate its order price |
| Database token theft | Random-IV AES-GCM; key kept outside database | Host compromise and leaked key expose tokens; metadata remains readable |
| Ciphertext substitution | Authenticated merchant/payment context | Entire host compromise bypasses application controls |
| Historical audit editing | Chained HMAC and startup verification | Tail truncation, whole snapshot rollback and key compromise need external checkpoints |
| Resource exhaustion | Body/header limits, timeouts, bounded rate-limit map | Per-process limits are not distributed DDoS protection |
| SQL injection | Bound query parameters | Host/database administrator access remains privileged |
| Accidental card retention | Exact allowlisted fields, synthetic token pattern, no request-body logs | Never submit real personal data, including in deliberately malformed requests |

The service currently audits accepted payment state changes. It does not persist security telemetry for rejected requests, manage administrative users or detect fraud patterns. It performs neither penetration testing nor automated incident response.

The local HTTP listener relies on loopback isolation. Browser access is not a security boundary; the API is intended for a merchant backend and has no CORS allowlist enabled. An internet deployment needs HTTPS, gateway/firewall configuration, access monitoring and independent review.
