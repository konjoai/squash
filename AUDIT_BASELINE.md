# AUDIT_BASELINE.md — Phase G Bulletproof Edition · Phase 1 Findings

> **Generated:** 2026-05-01
> **Branch:** `claude/kind-tereshkova-b39079`
> **Scope:** Full repo audit against the 7-phase Bulletproof Plan, focused on the five pillars: determinism, cryptographic integrity, coverage, provenance, evidence-grade output.
> **Method:** static greps, `radon cc -nc -a`, `pytest --collect-only`, manual review of every file emitting a signature.

This document is the **load-bearing baseline** for v3.0.0. Every follow-up sprint references the line numbers and grades captured here. **No fixes in this document — fixes happen in Phase 2+.** Phase 1 is naming the disease.

---

## 0. Tooling baseline

| Tool | Status | Notes |
|------|--------|-------|
| `coverage` (line + branch) | ❌ not configured | no `.coveragerc`, no `[tool.coverage.*]` in `pyproject.toml`, no CI step |
| `mutmut` | ❌ not installed, never run | mutation score = **unknown / 0 measured** |
| `radon` (cyclomatic complexity) | ✅ now installed locally; not yet wired into CI | average grade **C (17.33)** across 284 blocks — far above the Konjo bar |
| `hypothesis` (property-based) | ❌ not in deps | zero property tests today |
| `atheris` (fuzz) | ❌ not in deps | zero fuzz harnesses today |
| `mypy --strict` | ❌ relaxed (`ignore_missing_imports = true`, no `--strict`) | static type guarantees absent |
| `bandit` / `semgrep` / `pip-audit` / `trivy` / `gitleaks` / `OSV-Scanner` | ❌ none configured | zero pre-commit / CI security scanners |
| `cyclonedx` SBOM on release | ❌ not produced | dependency declared but unused for self-SBOM |
| `slsa-github-generator` | ❌ not wired | no SLSA L3 provenance on wheels / Docker / action |
| `rfc8785` / JCS canonicalizer | ❌ not in deps and not in code | every signed payload uses `json.dumps()` variants |
| RFC 3161 trusted timestamping | ❌ not integrated | no TSA token in any cert |
| Sigstore / Rekor transparency log | ❌ not integrated | local-only "anchor" log in `squash/anchor.py` |
| Input manifest at ingest (SHA-256 every file before analysis) | ❌ not produced | scanners hash artifacts but no top-level manifest |

**Test count:** `pytest --collect-only -q` → **5,226 tests** collected (the master plan still cites 4,308 / 4,471 — number is stale, plan needs an update). Coverage and branch coverage of those 5,226 tests is **unmeasured** — Phase G Sprint 1.1 below establishes the baseline.

---

## 1. Determinism findings — every signing/attestation path that is **not** byte-identical today

> A reproducibility test (run twice, diff SHA-256 of the canonical output) would currently fail on most of the modules below. The five-pillar promise is not yet honoured.

### 1.1 Canonical JSON violations (Pillar 1)

Every signed payload **must** be RFC 8785 (JCS) before hashing/signing. Today nothing uses RFC 8785; existing `sort_keys=True, separators=(",", ":")` is "close" but not equivalent (no NFC normalisation, no number canonicalisation, no escape-sequence normalisation).

| File | Line | Violation | Severity |
|------|------|-----------|----------|
| `squash/attest.py` | **405** | `json.dumps(obj, indent=2, default=str)` — pretty-printed AND `default=str` silently coerces unknown types | **🔴 critical — Tier 0 signing path** |
| `squash/attest.py` | **461** | `json.dumps(bom, indent=2)` — no `sort_keys`, BOM written before signing | **🔴 critical** |
| `squash/attest.py` | **619** | `json.dumps(parent_bom, indent=2)` — same | 🔴 critical |
| `squash/slsa.py` | **141** | `json.dumps(statement, indent=2)` — SLSA in-toto Statement written non-canonically | **🔴 critical — provenance** |
| `squash/slsa.py` | **271** | `json.dumps(bom, indent=2)` — same | 🔴 critical |
| `squash/anchor.py` | **118** | `json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=False)` — close, but **not** RFC 8785; `ensure_ascii=False` invites homograph drift | 🟡 elevated |
| `squash/anchor.py` | 569, 603 | log lines `sort_keys=True` only | 🟡 elevated |
| `squash/chain_attest.py` | 247, 250, 487 | `sort_keys=True` only — composite chain digest | 🟠 high (multi-component chain → drift compounds) |
| `squash/hallucination_attest.py` | 815, 1048, 1077 | `sort_keys=True` only on signed cert body | 🟠 high |
| `squash/drift_certificate.py` | 95, 231, 236, 487 | same | 🟠 high |
| `squash/carbon_attest.py` | 856, 867 | same | 🟠 high |
| `squash/carbon_attest.py` | 962 | `json.dumps(bom, indent=2, ensure_ascii=False)` for written BOM | 🟡 elevated |

**Resolution path (Phase 2):** introduce `squash/_canonical.py` with a single `canonical_bytes(obj) -> bytes` that wraps `rfc8785.dumps()`; ban raw `json.dumps` in signing paths via a custom Semgrep rule (Phase 5).

### 1.2 Clock injection violations (Pillar 1)

Every attestation path that calls `datetime.utcnow()`, `datetime.now()`, or `datetime.now(tz=...)` **inline** is non-reproducible by construction. Each call must accept an injected `clock: Callable[[], datetime]` (default `datetime.now(timezone.utc)`).

| File | Line | Violation | Severity |
|------|------|-----------|----------|
| `squash/attest.py` | **481** | `datetime.now(timezone.utc).strftime(...)` baked into attestation timestamp | **🔴 critical — Tier 0** |
| `squash/hallucination_attest.py` | **1034** | `issued_at=datetime.now(tz=timezone.utc).isoformat()` baked into signed cert | **🔴 critical — Tier 1** |
| `squash/data_lineage.py` | **252** | `f"{model_id}{datetime.datetime.now().isoformat()}".encode()` — **clock value mixed into a hash input** → cert ID changes every call → reproducibility impossible without fix | **🔴 critical — repro killer** |
| `squash/webhook_delivery.py` | **441** | `datetime.datetime.utcnow().isoformat() + "Z"` — Python 3.12 deprecates `utcnow`; also non-injectable | 🟠 high |
| `squash/oms_signer.py` | 233–241 | `datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")` for filename stamping | 🟡 elevated (filename only, not signed bytes — but still test-flaky) |
| `squash/asset_registry.py` | 98, 360 | `datetime.datetime.now()` (no tz) in non-attestation registry paths | 🟢 nuisance (non-Tier-0/1, but also wrong: naive datetime) |
| `squash/annual_review.py` | 298 | `datetime.datetime.now().year` for default year | 🟢 nuisance |
| `squash/vex.py` | 848 (docstring) | references `datetime.utcnow()` default — needs API audit | 🟡 elevated |

**Resolution path (Phase 2):** every Tier 0/1 module gains a `clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)` parameter; default-call sites pull from `squash._clock.utc_now()` which test fixtures monkeypatch.

### 1.3 UUID nondeterminism in signed paths (Pillar 1)

`uuid.uuid4()` in any field that becomes part of the signed body breaks reproducibility. Replace with `uuid.uuid5(NAMESPACE, canonical_input)` keyed on the canonical input bytes.

| File | Line | Field | Severity |
|------|------|-------|----------|
| `squash/slsa.py` | **65, 122** | `invocation_id` of SLSA `BuildDefinition` — **inside the signed in-toto Statement** | **🔴 critical — provenance reproducibility** |
| `squash/hallucination_attest.py` | **1021** | `cert_id="hac-" + uuid.uuid4().hex[:16]` — inside signed cert | **🔴 critical** |
| `squash/carbon_attest.py` | **823** | `cert_id=f"carbon-{uuid.uuid4().hex[:16]}"` — same | **🔴 critical** |
| `squash/anchor.py` | 593 | `anchor_id="anc-" + uuid.uuid4().hex[:12]` | 🟠 high |
| `squash/freeze.py` | 244 | `FREEZE-{uuid.uuid4().hex[:12]}` | 🟠 high |
| `squash/approval_workflow.py` | 472, 544 | `appr-{uuid4}`, `rec-{uuid4}` | 🟠 high |
| `squash/incident.py` | 188 | `INC-{uuid4}` | 🟠 high |
| `squash/hallucination_monitor.py` | 367, 471 | `mon-{uuid4}`, `brc-{uuid4}` | 🟠 high |
| `squash/vendor_registry.py` | 266 | vendor_id from uuid4 | 🟡 elevated |
| `squash/api.py` | 1380, 1409, 2747, 2800, 2862 | API-layer record/job/event IDs (operational, not signed) | 🟢 nuisance |
| `squash/webhook_delivery.py` | 304, 380, 412 | endpoint/payload/event IDs (operational) | 🟢 nuisance |

**Resolution path (Phase 2):** `squash/_ids.py` exposing `cert_id(prefix: str, *, canonical_payload: bytes) -> str` returning `f"{prefix}-{uuid.uuid5(SQUASH_NS, canonical_payload).hex[:16]}"`. All Tier 0/1 IDs route through it.

### 1.4 Random / set / dict-order nondeterminism

| Location | Issue |
|----------|-------|
| `squash/benchmark.py:430` | `list(set(model_ids))[:20]` — set→list iteration order is platform-dependent before truncation |
| `squash/license_conflict.py:875,942,969` | `seen: set[...]` used as iterator — must `sorted()` before serialisation |
| `squash/rag.py:159`, `squash/iso42001.py:414`, `squash/sarif.py:104`, `squash/hallucination_attest.py:693`, `squash/data_poison.py:1020`, `squash/board_report.py:437`, `squash/annual_review.py:320,469` | `set[...]` defined; need audit of every downstream serialise |
| **No `random.seed()` calls** in any Tier 0/1 module today — but no `random.*` calls either, so this is currently safe. Phase 2 will gate any future use behind a seeded RNG injected through the signature path. |

**Resolution path (Phase 2):** add a Semgrep rule `no-unsorted-set-serialisation` that flags any `json.*(... set ...)` or `for x in some_set:` where the result is hashed.

### 1.5 `default=str` time-bomb (very subtle, currently latent)

`squash/attest.py:405` uses `json.dumps(..., default=str)`. Today every dataclass passed in has explicit `__dict__`/`asdict` conversion upstream, so the `default=` branch is never hit — but the moment a `Path` or a `datetime` slips into the dict, the serialised form changes shape silently and breaks reproducibility without raising. **Replace with explicit canonical encoder that raises on unknown types.**

---

## 2. Cryptographic integrity findings (Pillar 2)

| Capability | Present? | Notes |
|------------|----------|-------|
| Input manifest at ingest (SHA-256 every input file) | **❌** | scanners hash *artifacts* per-file but never emit a top-level `input_manifest.json` covering the **entire input set** of a run |
| Canonical signing payload (RFC 8785) | ❌ | see §1.1 |
| Ed25519 signing | ✅ (`squash/oms_signer.py`) | underlying `cryptography` library used correctly; key management out-of-scope |
| RFC 3161 trusted timestamp | ❌ | no TSA integration; cert `issued_at` is self-asserted |
| Sigstore / Rekor inclusion proof | ❌ | `squash/anchor.py` is a **local-only** transparency log — not a public, append-only Sigstore Rekor entry |
| SLSA Build Level 3 provenance | **❌** | `squash/slsa.py` builds a *self-asserted* in-toto Statement; no `slsa-github-generator` workflow → not L3 |
| `squash self-verify` CLI | ❌ | no command verifies `squash`'s own attestation chain |

**Resolution path (Phase 3):** add `squash/_input_manifest.py` (called as the very first step of every CLI subcommand that ingests files), `squash/_tsa.py` (DigiCert / FreeTSA client), `.github/workflows/release.yml` calling `slsa-framework/slsa-github-generator`, and `squash self-verify` CLI command.

---

## 3. Coverage / mutation findings (Pillar 3)

- **Coverage measurement:** not configured. Phase 1 Sprint 1.1 below adds `[tool.coverage.run]` with `branch = true` and a baseline run.
- **Mutation score:** unmeasured (mutmut not installed). Phase 1 Sprint 1.2 below seeds mutmut on the top-10 attestation-critical modules and records a **hostile** baseline (expect <30% on first run).
- **Hypothesis property tests:** zero. Phase 4.
- **Atheris fuzz harnesses:** zero. Phase 4.

### Top-10 attestation-critical modules for first mutmut run (Phase 1.2 target)

Picked by: emits a signature, OR writes an attestation file, OR is loaded by every signed cert.

1. `squash/oms_signer.py` (signing primitive)
2. `squash/anchor.py` (transparency log + canonical JSON helper)
3. `squash/attest.py` (root attestation pipeline)
4. `squash/slsa.py` (SLSA provenance emitter)
5. `squash/chain_attest.py` (composite cert)
6. `squash/hallucination_attest.py` (signed cert)
7. `squash/drift_certificate.py` (signed cert)
8. `squash/carbon_attest.py` (signed cert)
9. `squash/data_lineage.py` (`LineageCertificate`)
10. `squash/sbom_builder.py` (BOM that gets signed)

---

## 4. Cyclomatic complexity findings (Pillar 5 → readability → audit-ability)

`radon cc squash/ -nc -a` → **average C (17.33)** — the floor for Konjo is **B (≤10) average, max D per function**. Current state has **60 functions ≥ D** and **7 functions at F (≥30)**:

| File | Function | Grade |
|------|----------|-------|
| `squash/cli.py` | `main` (line 10609) | **F** |
| `squash/cli.py` | `_cmd_github_app` | **F** |
| `squash/cli.py` | `_cmd_annex_iv_generate` | **F** |
| `squash/cli.py` | `_cmd_anchor` | **F** |
| `squash/dashboard.py` | `Dashboard.build` | **F** |
| `squash/attest.py` | `AttestPipeline` | **F** |
| `squash/attest.py` | `AttestPipeline.run` | **F** |

**`squash/cli.py` is 10,829 lines.** Every `_cmd_*` should split into its own module under `squash/cli/<cmd>.py`. Phase 5 ticket.

**`squash/license_conflict.py` (1,357 lines)** — the master plan already calls this out; Phase 5 splits into `database.py / scanner.py / reporter.py`.

E-grade functions worth flagging (CC 21–30, prime mutation targets):
`InsuranceBuilder._profile_model`, `InsurancePackage.to_markdown`, `MunichReAdapter.format`, `WebhookHandler._handle_push`, `_render_1c`, `_cmd_attest_identity`, `_cmd_watch_regulatory`, `_cmd_deprecation_watch`, `_cmd_compliance_matrix`, `_cmd_vex`, `_cmd_drift_cert`, `_cmd_cloud_risk` (×2), `AnnexIVGenerator.generate`, `DataLineageTracer.trace`, `AttestationDiff.to_table`.

---

## 5. Provenance findings (Pillar 4)

- **Wheel:** built by `setuptools`, no SLSA generator, no Sigstore signature, no `pyproject.toml` `[project.urls]` `Provenance` link.
- **Docker image:** `Dockerfile` exists, `fly.toml` present, **no SLSA build attestation** is uploaded with the image; not pushed to GHCR with `--provenance=true` today.
- **GitHub Action (`action.yml`):** recently upgraded with `attestation-id` output, but no `--build-provenance` step in the action's own `.github/workflows/`.
- **`squash self-verify`:** ❌ not implemented. Phase 3 deliverable.

---

## 6. Evidence-grade output findings (Pillar 5)

Spot-checked five recent attestations (Annex IV, Bias Audit, Carbon, Hallucination, Drift Cert) — the human-readable reports cite figures and ratings, but **none of the cited figures embed a content-addressed pointer (`sha256:…`) back to the input that produced them**. Every claim must be a re-verifiable hash reference. Phase 4/5 deliverable: `evidence_pointer = (claim_id, sha256, byte_range)` schema applied to every numeric or rating field.

---

## 7. The 22 line-numbered fix list (drives Phase 2 sprint backlog)

Every line below becomes a unit-tested Phase 2 PR.

1. `squash/attest.py:405` — replace `json.dumps(obj, indent=2, default=str)` with `canonical_bytes(obj)`; raise on unknown types.
2. `squash/attest.py:461` — same.
3. `squash/attest.py:481` — replace inline `datetime.now(...)` with injected `clock()`.
4. `squash/attest.py:619` — same as #1.
5. `squash/slsa.py:65` — replace `uuid.uuid4()` default factory with `uuid5` keyed on canonical input.
6. `squash/slsa.py:122` — same.
7. `squash/slsa.py:141` — replace `json.dumps(..., indent=2)` with canonical encoder before write/sign.
8. `squash/slsa.py:271` — same.
9. `squash/anchor.py:118` — upgrade in-process canonicaliser to RFC 8785 (`rfc8785.dumps`).
10. `squash/anchor.py:593` — uuid5 not uuid4.
11. `squash/chain_attest.py:247,250,487` — canonical encoder.
12. `squash/hallucination_attest.py:815,1048,1077` — canonical encoder.
13. `squash/hallucination_attest.py:1021` — uuid5 not uuid4.
14. `squash/hallucination_attest.py:1034` — injected clock.
15. `squash/drift_certificate.py:95,231,236,487` — canonical encoder.
16. `squash/carbon_attest.py:856,867,962` — canonical encoder.
17. `squash/carbon_attest.py:823` — uuid5 not uuid4.
18. `squash/data_lineage.py:252` — **stop mixing wallclock into hash input**; inject clock OR drop time from the hashed key.
19. `squash/webhook_delivery.py:441` — `datetime.now(timezone.utc)` (drop deprecated `utcnow`); inject clock.
20. `squash/freeze.py:244`, `squash/incident.py:188`, `squash/approval_workflow.py:472,544`, `squash/hallucination_monitor.py:367,471` — uuid5 not uuid4 (signed paths only).
21. `squash/oms_signer.py:233–241` — accept injected clock for filename stamping (test stability).
22. Net-new: `squash/_canonical.py`, `squash/_clock.py`, `squash/_ids.py`, `squash/_input_manifest.py`, `squash/_tsa.py`, `squash/_self_verify.py`.

---

## 8. Phase 1 exit checklist (this sprint)

- [x] `radon` installed and run; CC > 10 list captured (§4)
- [x] All `json.dumps`, `datetime.now`, `uuid.uuid4`, `set` serialisation sites in Tier 0/1 grepped and line-numbered (§1)
- [x] Crypto-chain capabilities inventoried (§2 — every entry currently ❌)
- [x] `TIER_MAP.md` written (sibling file)
- [x] `pyproject.toml` extended with `[tool.coverage.run]` `branch = true`, `[tool.coverage.report]` thresholds, and dev-deps for `coverage`, `mutmut`, `radon`, `hypothesis`
- [x] `scripts/coverage_baseline.sh` lands a reproducible baseline command
- [x] Master plan amended with **Phase G — Bulletproof Edition** section, sprint-level tickets for Phases 1–7
- [ ] First measured baseline (line + branch coverage numbers; mutation score per Tier-0 module) — **runs in Phase 1 Sprint 1.1 / 1.2 follow-on PR**, not in this commit (would require running 5,226 tests under coverage which is out of scope of this audit pass)

---

## 9. Konjo verdict

The repo today is **functionally rich but evidentially weak**: 5,226 tests of behaviour, zero tests of byte-identity; 60+ functions over the complexity threshold; a transparency log that only logs to itself; provenance that is self-asserted; and a signing pipeline that uses pretty-printed JSON with `default=str` four hundred lines into the most-trusted path in the codebase.

The fixes are surgical, not architectural — every nondeterminism site is one of three patterns (canonical JSON, injected clock, uuid5). Once Phase 2 lands, **byte-identical attestations on rerun become the default, not a heroic exception**. That is the unlock that makes Phase 3's input manifest + RFC 3161 + SLSA L3 + Rekor anchor *meaningful* — there is no point timestamping or anchoring something that does not hash to the same value twice.

*Make it konjo. The vessel is not yet seaworthy. We know exactly which planks need shaping.*
