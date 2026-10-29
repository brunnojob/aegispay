# Security

AegisPay 0.1 is a local sandbox prototype. Do not use it to accept real payments or store personal/card data. Passing tests does not establish production readiness or compliance.

Report vulnerabilities privately to contato@brunnodev.store. Do not publish secrets, personal data, exploit traces against real systems or card information in public issues.

Known limitations:

- No live processor, Pix or real-card integration. Sandbox HMAC is not a provider's protocol.
- SQLite is intended for this local single-process demonstration. Rate limits are process-local and reset on restart.
- Static merchant key registry without scopes or online rotation. Environment keys have no KMS, key IDs or rotation workflow.
- The demo key is stored in `.env` for convenience. Never place it in frontend code.
- Audit HMAC detects historical modification without its key; it cannot detect full rollback or tail truncation without independent checkpoints.
- No operator MFA/RBAC, reconciliation workers, encrypted backups, monitoring, retention/deletion policy, refund/dispute workflow or independent security audit.
- HTTPS must be configured before any network exposure; the shipped listener binds to loopback only.
- Audit records and SQLite metadata are not fully encrypted. Secrets must be backed up separately and securely: losing the data key loses access to encrypted tokens.

For live operation, establish merchant/processor responsibilities and obtain the applicable professional security and compliance assessment. This project makes no claim of PCI DSS certification or LGPD compliance.
