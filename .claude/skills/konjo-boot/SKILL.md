---
name: konjo-boot
description: Boot a Konjo session for squash. Produces a Session Brief, runs Discovery, identifies the next sprint.
user-invocable: true
---
# Konjo Session Boot — squash

## Step 1 — Read
Read: CLAUDE.md, README.md, CHANGELOG.md, SQUASH_MASTER_PLAN.md, TIER_MAP.md, AUDIT_BASELINE.md, docs/.

## Step 2 — Session Brief
```
REPO         squash — AI compliance tool (EU AI Act, NIST RMF, OWASP LLM Top-10). Deadline: 2026-08-02.
LAST SHIPPED [most recent change from CHANGELOG.md]
OPEN WORK    [from SQUASH_MASTER_PLAN.md]
BLOCKERS     [failing tests, open blockers]
HEALTH       [Green / Yellow / Red]
```

## Step 3 — Discovery
Search: regulatory updates (EU AI Act, NIST), OWASP LLM Top-10 updates, CycloneDX/SPDX ML-BOM, Sigstore adoption.

## Step 4 — Identify Work
Load SQUASH_MASTER_PLAN.md + TIER_MAP.md. Validate against codebase. Flag drift. EU deadline is Aug 2, 2026.

## Invocation Keywords: `konjo` / `konjo squash` / `squash konjo` / `read KONJO_PROMPT.md and begin`
