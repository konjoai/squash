# Acme AI — SOC 2 Type II Trust Services Criteria Summary

## Security (Common Criteria)

- **CC6.1 — Logical access.** Access to production systems requires SSO with
  hardware-key MFA. All privileged operations are logged to an append-only
  audit trail retained for 7 years.
- **CC6.6 — Encryption.** All data is encrypted at rest (AES-256) and in
  transit (TLS 1.3 with HSTS). Customer-managed keys are available on the
  Enterprise plan.
- **CC7.2 — Monitoring.** A 24×7 SOC monitors signals from EDR, network IDS,
  cloud audit logs, and application telemetry. Mean time to detect: 7 minutes;
  mean time to respond: 28 minutes.
- **CC7.4 — Incident response.** Incidents are managed under a documented IR
  plan reviewed quarterly. Customers are notified of incidents affecting their
  data within 24 hours.

## Availability

- 99.95% monthly uptime SLA. Multi-region active-active architecture with
  automated failover. Disaster-recovery runbooks tested twice a year.

## Confidentiality

- Customer data is logically isolated. Internal access requires a documented
  business need, reviewed quarterly. Data is purged within 30 days of contract
  termination.

## Processing integrity

- Every model invocation is logged with input hash, model version, and output
  hash. Reproducibility is verified weekly via a regression suite.

## Privacy

- We process personal information only as instructed by the customer (the
  controller). A Data Processing Addendum is included by default. Sub-processors
  are listed publicly and notified 30 days before engagement.

Audited by an independent CPA firm. Report available under NDA on request.
