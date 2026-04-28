# Changelog

All notable changes to `squash-ai` are documented here.
Format: [Conventional Commits](https://www.conventionalcommits.org/) · [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [Unreleased]

## [0.9.14] — 2026-04-28

### Changed
- **repo separation**: Extracted from `konjoai/squish` into standalone `konjoai/squash` repository via `git filter-repo` with full git history preserved
- All `squish.squash` import paths updated to `squash` across 112 source files
- `import squish` version references replaced with `import squash as squish` in `sbom_builder.py`, `attest.py`, `spdx_builder.py`
- `squash/__init__.py` updated: standalone docstring, `__version__ = "0.9.14"` added
- `pyproject.toml`: standalone `squash-ai` package, Apache 2.0 license, modular extras (`api`, `signing`, `sbom`, `integrations`, `dev`)
- `CLAUDE.md`: squash-specific contributor conventions (squash hard rules, compliance framework coverage, API contracts)
- `SQUASH_MASTER_PLAN.md`: master GTM plan from zero to $10M ARR committed to repo
- `README.md`: developer-first landing page with EU AI Act countdown framing
- `.github/workflows/ci.yml`: pytest matrix (Python 3.10/3.11/3.12), ruff lint, security audit
- `.github/workflows/publish.yml`: trusted PyPI publishing on release

### Added (Wave 83 — from squish extraction)
- `squash/nist_rmf.py`: NIST AI RMF 1.0 controls scanner (`NistRmfScanner`, 42 controls across GOVERN·MAP·MEASURE·MANAGE)

### Added (Wave 82 — from squish extraction)
- HQQ (Half-Quadratic Quantization) float precision metadata in SBOM components

### Previous waves (W57–W81)
Extracted with full git history. See `git log --oneline` for complete wave history.

---

*For full history prior to repo separation, see [konjoai/squish](https://github.com/konjoai/squish) git history.*
