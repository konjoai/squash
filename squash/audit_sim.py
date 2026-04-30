"""squash/audit_sim.py — Sprint 22 W229–W231 (Track C / C5).

Regulatory Examination Simulation Engine: ``squash simulate-audit``.

The premise: 78% of business executives lack confidence they could pass
an independent AI governance audit within 90 days (Grant Thornton 2026).
This module runs a mock examination *from the regulator's perspective*,
pulls answers from the model's squash attestation artefacts, flags gaps
where evidence is missing, and produces an executive-ready readiness
report — the $5K–$15K professional-service deliverable compressed into
a 60-second CLI command.

Architecture
============

``ExamQuestion``
    A single examiner question: what article it comes from, what squash
    artefact files would answer it, which CLI commands generate that
    evidence, and how critical it is (weight 1–3; weight-3 = critical gate).

``ExamAnswer``
    The engine's answer for one question: PASS / PARTIAL / FAIL,
    evidence found/missing, gap description, remediation step, and a
    squash command the org can run *right now* to close the gap.

``ReadinessReport``
    Aggregate: overall score 0–100, readiness tier, critical-gate
    summary, prioritised remediation roadmap, executive summary, and
    renders to JSON + Markdown.

``AuditSimulator``
    Stateless. ``.simulate(model_path, regulator)`` → ``ReadinessReport``.
    Evidence detection is file-presence based (no network calls) so it
    runs instantly in air-gapped CI.

Regulator profiles
==================

``EU-AI-Act``   38 questions covering Art. 9–15, 17, 73, Annex IV,
                and conformity assessment for high-risk AI.
``NIST-RMF``    30 questions spanning GOVERN, MAP, MEASURE, MANAGE.
``SEC``         22 questions on AI disclosure, material risk, ops controls,
                and investment-adviser obligations (OMB M-26-04 ready).
``FDA``         20 questions on SaMD risk, clinical validation, post-market,
                bias/fairness, and device labelling.

Scoring
=======

Each question contributes ``question.weight × points_for_status`` to the
total score, where ``points_for_status`` = 2 (PASS) / 1 (PARTIAL) / 0 (FAIL).

``overall_score = 100 × Σ(earned) / Σ(max_possible)``

**Critical-gate cap:** any weight-3 question that scores FAIL caps the
total at 74 (just below "Substantial") regardless of other scores.

Tiers::

    AUDIT_READY   ≥ 80 · no critical fails
    SUBSTANTIAL   60–79 (or 74 cap from critical fail)
    DEVELOPING    40–59
    EARLY_STAGE   < 40

Stdlib-only. No external dependencies. Evidence detection is pure
filesystem introspection against a local model directory.
"""

from __future__ import annotations

import datetime
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── Known squash artefact filenames ───────────────────────────────────────────

# Canonical squash artefact names — searched inside model_path/ and model_path/squash/
_ATTEST        = "squash-attest.json"
_ATTEST_ALT    = "squash_attestation.json"
_BOM           = "cyclonedx-mlbom.json"
_SPDX          = "spdx-mlbom.json"
_SCAN          = "squash-scan.json"
_VEX           = "squash-vex-report.json"
_ANNEX_IV      = "annex_iv.json"
_MODEL_CARD    = "squash-model-card-hf.md"
_BIAS          = "bias_audit_report.json"
_LINEAGE       = "data_lineage_certificate.json"
_INCIDENT      = "squash-incident.json"
_DRIFT         = "squash-drift.json"
_NIST_RMF      = "nist_rmf_report.json"
_SQUASH_CFG    = ".squash.yml"
_SQUASH_JSON   = "squish.json"
_POLICY_PREFIX = "squash-policy-"  # matches squash-policy-eu-ai-act.json etc.
_CHAIN_ATTEST  = "chain-attest.json"
_REG_GATE      = "registry-gate.json"
_SBOM_DIFF     = "squash-sbom-diff.json"

_ALL_KNOWN = frozenset({
    _ATTEST, _ATTEST_ALT, _BOM, _SPDX, _SCAN, _VEX, _ANNEX_IV,
    _MODEL_CARD, _BIAS, _LINEAGE, _INCIDENT, _DRIFT, _NIST_RMF,
    _SQUASH_CFG, _SQUASH_JSON, _CHAIN_ATTEST, _REG_GATE, _SBOM_DIFF,
})


# ── Core data classes ─────────────────────────────────────────────────────────


@dataclass
class ExamQuestion:
    """A single examiner question with evidence pointers.

    Attributes:
        q_id:           Unique question ID (e.g. ``"EU-001"``).
        article:        Regulatory article/section (e.g. ``"Art. 9(1)a"``).
        question:       The examiner's question text.
        answer_sources: Squash artefact filenames that answer this question.
                        Any one present → PARTIAL; all present → PASS.
        answer_cli:     Squash CLI commands that generate the missing evidence.
        weight:         1 = standard · 2 = important · 3 = critical gate.
        category:       Thematic category (e.g. ``"risk-management"``).
        days_to_close:  Estimated engineer-days to produce evidence.
    """

    q_id: str
    article: str
    question: str
    answer_sources: list[str]
    answer_cli: list[str]
    weight: int = 2
    category: str = "general"
    days_to_close: int = 3


@dataclass
class ExamAnswer:
    """Engine answer for one examiner question."""

    question: ExamQuestion
    status: str                  # "PASS" | "PARTIAL" | "FAIL" | "N/A"
    evidence_found: list[str] = field(default_factory=list)
    evidence_missing: list[str] = field(default_factory=list)
    gap_description: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "q_id": self.question.q_id,
            "article": self.question.article,
            "question": self.question.question,
            "category": self.question.category,
            "weight": self.question.weight,
            "status": self.status,
            "evidence_found": list(self.evidence_found),
            "evidence_missing": list(self.evidence_missing),
            "gap_description": self.gap_description,
            "remediation": self.remediation,
            "squash_commands": list(self.question.answer_cli),
            "days_to_close": self.question.days_to_close,
        }


@dataclass
class ReadinessReport:
    """Aggregate examination result with score, tier, and remediation plan."""

    regulator: str
    model_path: str
    generated_at: str
    overall_score: int
    readiness_tier: str           # AUDIT_READY|SUBSTANTIAL|DEVELOPING|EARLY_STAGE
    answers: list[ExamAnswer]
    critical_fails: int
    total_questions: int
    passing: int
    partial: int
    failing: int
    high_priority_gaps: list[str] = field(default_factory=list)
    executive_summary: str = ""
    squash_version: str = "audit_sim_v1"

    # ── Serialisation ─────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "squash_version": self.squash_version,
            "regulator": self.regulator,
            "model_path": self.model_path,
            "generated_at": self.generated_at,
            "overall_score": self.overall_score,
            "readiness_tier": self.readiness_tier,
            "summary": {
                "total_questions": self.total_questions,
                "passing": self.passing,
                "partial": self.partial,
                "failing": self.failing,
                "critical_fails": self.critical_fails,
            },
            "high_priority_gaps": list(self.high_priority_gaps),
            "executive_summary": self.executive_summary,
            "answers": [a.to_dict() for a in self.answers],
            "remediation_roadmap": self._roadmap_dicts(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_markdown(self) -> str:
        tier_emoji = {
            "AUDIT_READY":   "✅",
            "SUBSTANTIAL":   "🟡",
            "DEVELOPING":    "🟠",
            "EARLY_STAGE":   "🔴",
        }.get(self.readiness_tier, "⚪")

        lines: list[str] = [
            f"# {self.regulator} Regulatory Examination Simulation",
            "",
            f"**Model:** `{self.model_path}`  ",
            f"**Generated:** {self.generated_at[:10]}  ",
            f"**Readiness:** {tier_emoji} **{self.readiness_tier.replace('_', ' ')}**  ",
            f"**Score:** {self.overall_score}/100",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            self.executive_summary,
            "",
            "## Scorecard",
            "",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Overall score | **{self.overall_score}**/100 |",
            f"| Readiness tier | {self.readiness_tier.replace('_', ' ')} |",
            f"| Questions answered (PASS) | {self.passing}/{self.total_questions} |",
            f"| Partially answered | {self.partial} |",
            f"| Gaps (FAIL) | {self.failing} |",
            f"| Critical gate fails | {self.critical_fails} |",
            "",
        ]

        # Category breakdown
        categories: dict[str, list[ExamAnswer]] = {}
        for ans in self.answers:
            cat = ans.question.category
            categories.setdefault(cat, []).append(ans)

        lines.extend(["## Results by Category", ""])
        for cat, answers in sorted(categories.items()):
            passing = sum(1 for a in answers if a.status == "PASS")
            total = len(answers)
            pct = int(100 * passing / total)
            bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
            lines.append(
                f"**{cat.replace('-', ' ').title()}** {bar} {pct}% "
                f"({passing}/{total})"
            )
        lines.extend(["", "## Question Detail", ""])

        for ans in self.answers:
            icon = {"PASS": "✅", "PARTIAL": "🟡", "FAIL": "❌", "N/A": "⊘"}.get(
                ans.status, "?"
            )
            weight_star = "★" * ans.question.weight
            lines.extend([
                f"### {ans.question.q_id} — {icon} {ans.question.article}",
                "",
                f"**{ans.question.question}**",
                "",
                f"*Weight: {weight_star} · Category: {ans.question.category}*",
                "",
            ])
            if ans.evidence_found:
                lines.append("Evidence found:")
                for ev in ans.evidence_found:
                    lines.append(f"  - `{ev}`")
            if ans.evidence_missing:
                lines.append("Evidence missing:")
                for ev in ans.evidence_missing:
                    lines.append(f"  - `{ev}`")
            if ans.gap_description:
                lines.extend(["", f"> **Gap:** {ans.gap_description}"])
            if ans.remediation and ans.status != "PASS":
                lines.extend(["", f"**Remediation:** {ans.remediation}"])
                if ans.question.answer_cli:
                    lines.append("")
                    lines.append("Run:")
                    for cmd in ans.question.answer_cli[:2]:
                        lines.append(f"```bash\n{cmd}\n```")
            lines.append("")

        # Remediation roadmap
        roadmap = self._roadmap()
        if roadmap:
            lines.extend([
                "---",
                "",
                "## 90-Day Remediation Roadmap",
                "",
                "Sequenced to maximise compliance score per engineering-day invested.",
                "",
                "| Priority | Gap | Squash command | Days |",
                "|---|---|---|---|",
            ])
            day_counter = 0
            for item in roadmap:
                day_counter += item["days_to_close"]
                lines.append(
                    f"| **{item['priority']}** | {item['article']}: "
                    f"{item['q_id']} | `{item['command']}` | {item['days_to_close']} |"
                )
            lines.extend([
                "",
                f"**Estimated total remediation effort: {day_counter} engineer-days**",
                "",
            ])

        lines.extend([
            "---",
            "",
            "*Generated by [squash](https://getsquash.dev) · "
            f"`squash simulate-audit --regulator {self.regulator}` · "
            "Squash violations, not velocity.*",
        ])
        return "\n".join(lines) + "\n"

    def save(
        self,
        output_dir: Path | str,
        stem: str = "audit-readiness",
    ) -> dict[str, Path]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}
        p = output_dir / f"{stem}.json"
        p.write_text(self.to_json(), encoding="utf-8")
        written["json"] = p
        p = output_dir / f"{stem}.md"
        p.write_text(self.to_markdown(), encoding="utf-8")
        written["md"] = p
        return written

    # ── Private ───────────────────────────────────────────────────────────

    def _roadmap(self) -> list[dict[str, Any]]:
        """Prioritised remediation list for failed/partial answers."""
        items: list[dict[str, Any]] = []
        for ans in self.answers:
            if ans.status in ("FAIL", "PARTIAL"):
                cmd = ans.question.answer_cli[0] if ans.question.answer_cli else "squash attest"
                items.append({
                    "q_id": ans.question.q_id,
                    "article": ans.question.article,
                    "weight": ans.question.weight,
                    "status": ans.status,
                    "command": cmd,
                    "days_to_close": ans.question.days_to_close,
                    "priority": (
                        "CRITICAL" if ans.question.weight == 3 else
                        "HIGH" if ans.question.weight == 2 else "MEDIUM"
                    ),
                })
        # Sort: critical first, then weight desc, then days asc (quick wins)
        items.sort(key=lambda x: (-x["weight"], x["days_to_close"]))
        return items

    def _roadmap_dicts(self) -> list[dict[str, Any]]:
        return self._roadmap()


# ── Simulation engine ─────────────────────────────────────────────────────────


class AuditSimulator:
    """Stateless regulatory examination simulator.

    Usage::

        report = AuditSimulator().simulate(
            model_path=Path("./my-model"),
            regulator="EU-AI-Act",
        )
        report.save("./out")
        print(report.to_markdown())
    """

    SUPPORTED_REGULATORS: frozenset[str] = frozenset({
        "EU-AI-Act", "NIST-RMF", "SEC", "FDA",
    })

    def simulate(
        self,
        model_path: Path | str,
        regulator: str,
    ) -> ReadinessReport:
        """Run the mock examination and return a ``ReadinessReport``.

        Args:
            model_path: Path to a model directory containing squash artefacts.
            regulator:  One of ``"EU-AI-Act"``, ``"NIST-RMF"``, ``"SEC"``,
                        ``"FDA"``.

        Raises:
            ValueError: If ``regulator`` is not supported.
        """
        model_path = Path(model_path)
        reg = regulator.upper().replace(" ", "-")
        # Normalise aliases
        _aliases = {"EU": "EU-AI-ACT", "NIST": "NIST-RMF", "EU-AI-ACT": "EU-AI-ACT"}
        reg = _aliases.get(reg, reg)

        profile_fn = {
            "EU-AI-ACT": _eu_ai_act_questions,
            "EU-AI-Act".upper().replace(" ", "-"): _eu_ai_act_questions,
            "NIST-RMF": _nist_rmf_questions,
            "SEC": _sec_questions,
            "FDA": _fda_questions,
        }.get(reg.upper())
        if profile_fn is None:
            raise ValueError(
                f"Unsupported regulator: {regulator!r}. "
                f"Supported: {sorted(self.SUPPORTED_REGULATORS)}"
            )

        questions = profile_fn()
        artifacts = _collect_artifacts(model_path)
        answers = [_answer_question(q, artifacts, model_path) for q in questions]

        score, tier, critical_fails = _compute_score(answers)
        passing = sum(1 for a in answers if a.status == "PASS")
        partial = sum(1 for a in answers if a.status == "PARTIAL")
        failing = sum(1 for a in answers if a.status == "FAIL")
        high_gaps = [
            f"{a.question.q_id} ({a.question.article}): {a.gap_description}"
            for a in answers
            if a.status == "FAIL" and a.question.weight == 3
        ]
        summary = _executive_summary(regulator, score, tier, passing,
                                      partial, failing, critical_fails,
                                      len(questions))
        return ReadinessReport(
            regulator=regulator,
            model_path=str(model_path),
            generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            overall_score=score,
            readiness_tier=tier,
            answers=answers,
            critical_fails=critical_fails,
            total_questions=len(questions),
            passing=passing,
            partial=partial,
            failing=failing,
            high_priority_gaps=high_gaps,
            executive_summary=summary,
        )


# ── Evidence detection ────────────────────────────────────────────────────────


def _collect_artifacts(model_path: Path) -> set[str]:
    """Return the set of squash artefact filenames present in model_path."""
    present: set[str] = set()
    if not model_path.exists():
        return present
    for search_dir in (model_path, model_path / "squash"):
        if not search_dir.is_dir():
            continue
        for child in search_dir.iterdir():
            nm = child.name
            if nm in _ALL_KNOWN or nm.startswith(_POLICY_PREFIX):
                present.add(nm)
    return present


def _answer_question(
    q: ExamQuestion,
    artifacts: set[str],
    model_path: Path,
) -> ExamAnswer:
    """Score one examiner question against the available evidence."""
    required = list(q.answer_sources)
    found = [s for s in required if s in artifacts]
    missing = [s for s in required if s not in artifacts]

    # Special case: policy prefix match
    for s in list(missing):
        if s == _POLICY_PREFIX:
            if any(a.startswith(_POLICY_PREFIX) for a in artifacts):
                missing.remove(s)
                found.append(s)

    ratio = len(found) / max(len(required), 1)
    if not required:
        status = "N/A"
        gap = ""
        remediation = ""
    elif ratio >= 0.85:
        status = "PASS"
        gap = ""
        remediation = ""
    elif ratio > 0:
        status = "PARTIAL"
        gap = (
            f"Some evidence present but {len(missing)} artefact(s) missing: "
            f"{', '.join(missing[:3])}."
        )
        cmd = q.answer_cli[0] if q.answer_cli else "squash attest"
        remediation = f"Generate missing evidence: `{cmd}`"
    else:
        status = "FAIL"
        gap = (
            f"No evidence found. Required artefact(s): "
            f"{', '.join(missing[:3])}."
        )
        cmd = q.answer_cli[0] if q.answer_cli else "squash attest"
        remediation = (
            f"No squash artefacts found for this requirement. "
            f"Start with: `{cmd}`"
        )

    return ExamAnswer(
        question=q,
        status=status,
        evidence_found=found,
        evidence_missing=missing,
        gap_description=gap,
        remediation=remediation,
    )


def _compute_score(
    answers: list[ExamAnswer],
) -> tuple[int, str, int]:
    """Return (overall_score_0_100, readiness_tier, critical_fail_count)."""
    _POINTS = {"PASS": 2, "PARTIAL": 1, "FAIL": 0, "N/A": 0}
    earned = sum(a.question.weight * _POINTS[a.status] for a in answers)
    max_pts = sum(a.question.weight * 2 for a in answers if a.status != "N/A")
    raw = int(100 * earned / max(max_pts, 1))

    critical_fails = sum(
        1 for a in answers if a.question.weight == 3 and a.status == "FAIL"
    )
    score = min(raw, 74) if critical_fails > 0 else raw
    score = max(0, min(100, score))

    if score >= 80 and critical_fails == 0:
        tier = "AUDIT_READY"
    elif score >= 60:
        tier = "SUBSTANTIAL"
    elif score >= 40:
        tier = "DEVELOPING"
    else:
        tier = "EARLY_STAGE"
    return score, tier, critical_fails


def _executive_summary(
    regulator: str,
    score: int,
    tier: str,
    passing: int,
    partial: int,
    failing: int,
    critical_fails: int,
    total: int,
) -> str:
    tier_desc = {
        "AUDIT_READY":   "examination-ready with strong evidence coverage",
        "SUBSTANTIAL":   "substantially prepared, with targeted gaps to close",
        "DEVELOPING":    "in active development of compliance evidence",
        "EARLY_STAGE":   "at an early stage of compliance evidence generation",
    }.get(tier, "assessed")

    crit_note = (
        f" **{critical_fails} critical-gate requirement(s) are missing** — "
        "these must be addressed before examination regardless of overall score."
        if critical_fails else " No critical-gate requirements are missing."
    )

    gap_sentence = (
        f"Of {total} examiner questions, **{passing} answered** (PASS), "
        f"**{partial} partially answered** (PARTIAL), and "
        f"**{failing} unanswered** (FAIL)."
    )

    return (
        f"This model portfolio is **{tier_desc}** for a {regulator} regulatory "
        f"examination, with an overall readiness score of **{score}/100**. "
        f"{gap_sentence}{crit_note} "
        f"The remediation roadmap below is sequenced by weight and effort — "
        f"following it will produce audit-ready evidence in the shortest elapsed time."
    )


# ── Regulator profiles ────────────────────────────────────────────────────────
# Each function returns the ordered list of examiner questions.
# Questions are ordered: critical gates first, then high-weight, then standard.
# Reference source for EU AI Act: Regulation (EU) 2024/1689.
# Reference source for NIST RMF: NIST AI 100-1.
# Reference source for SEC: OMB M-26-04, SEC AI priorities 2026.
# Reference source for FDA: FDA AI/ML-Based SaMD Action Plan.


def _eu_ai_act_questions() -> list[ExamQuestion]:
    """38 examiner questions for EU AI Act (Regulation (EU) 2024/1689)."""
    return [
        # ── Critical gates (weight 3) ─────────────────────────────────────
        ExamQuestion(
            q_id="EU-001", article="Art. 9(1)", weight=3, category="risk-management",
            question="Has the organisation established and maintained a risk management system for this AI system throughout its lifecycle?",
            answer_sources=[_ATTEST, _SCAN, "squash-policy-eu-ai-act.json"],
            answer_cli=["squash attest --policy eu-ai-act", "squash risk-assess"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-002", article="Art. 11(1)", weight=3, category="technical-documentation",
            question="Is the technical documentation (Annex IV) complete and current, covering all 12 sections?",
            answer_sources=[_ANNEX_IV, _BOM],
            answer_cli=["squash annex-iv generate --format all", "squash attest"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-003", article="Art. 14(1)", weight=3, category="human-oversight",
            question="Are human oversight measures implemented and documented for this AI system?",
            answer_sources=[_ANNEX_IV, _ATTEST],
            answer_cli=["squash annex-iv generate", "squash attest --policy eu-ai-act"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-004", article="Art. 13(1)", weight=3, category="transparency",
            question="Has the AI system been designed to enable transparency and interpretability for deployers?",
            answer_sources=[_MODEL_CARD, _ANNEX_IV],
            answer_cli=["squash model-card --format all", "squash annex-iv generate"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-005", article="Art. 73(1)", weight=3, category="incident-reporting",
            question="Are procedures in place to report serious incidents to market surveillance authorities within 15 working days?",
            answer_sources=[_INCIDENT, _ATTEST],
            answer_cli=["squash incident --type serious", "squash freeze --help"],
            days_to_close=5,
        ),
        # ── High weight (weight 2) ────────────────────────────────────────
        ExamQuestion(
            q_id="EU-006", article="Art. 10(2)", weight=2, category="data-governance",
            question="Have training, validation, and testing data sets been governed with documented provenance and quality criteria?",
            answer_sources=[_LINEAGE, _ANNEX_IV],
            answer_cli=["squash data-lineage --model ./model", "squash annex-iv generate"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-007", article="Art. 10(5)", weight=2, category="data-governance",
            question="Have the datasets been assessed for potential biases that could produce discriminatory outputs?",
            answer_sources=[_BIAS, _ANNEX_IV],
            answer_cli=["squash bias-audit --model ./model", "squash annex-iv generate"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="EU-008", article="Art. 12(1)", weight=2, category="record-keeping",
            question="Are logs automatically generated and retained to enable post-market monitoring?",
            answer_sources=[_ATTEST, _SCAN, _DRIFT],
            answer_cli=["squash attest --sign", "squash drift-check"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-009", article="Art. 15(1)", weight=2, category="accuracy-robustness",
            question="Has the AI system been validated for accuracy, robustness, and cybersecurity appropriate to its intended purpose?",
            answer_sources=[_SCAN, _VEX, "squash-policy-eu-ai-act.json"],
            answer_cli=["squash scan ./model", "squash vex update", "squash attest --policy eu-ai-act"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-010", article="Art. 15(3)", weight=2, category="accuracy-robustness",
            question="Are measures in place to protect against adversarial attacks and model poisoning?",
            answer_sources=[_SCAN, _VEX],
            answer_cli=["squash scan ./model --exit-2-on-unsafe", "squash vex update"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-011", article="Art. 9(4)", weight=2, category="risk-management",
            question="Have residual risks been evaluated and documented after risk mitigation measures?",
            answer_sources=["squash-policy-eu-ai-act.json", _ANNEX_IV],
            answer_cli=["squash risk-assess", "squash annex-iv generate"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-012", article="Art. 9(9)", weight=2, category="risk-management",
            question="Is the risk management system subject to continuous updates based on post-market monitoring data?",
            answer_sources=[_DRIFT, _ATTEST],
            answer_cli=["squash drift-check --baseline ./baseline.json", "squash watch"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-013", article="Art. 10(3)", weight=2, category="data-governance",
            question="Have data preparation pipelines been documented including pre-processing steps?",
            answer_sources=[_LINEAGE, _BOM],
            answer_cli=["squash data-lineage --model ./model", "squash attest"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-014", article="Art. 16(a)", weight=2, category="conformity",
            question="Has the provider established and maintained a quality management system (QMS) for this AI system?",
            answer_sources=[_ATTEST, _SQUASH_CFG],
            answer_cli=["squash init", "squash attest --policy eu-ai-act"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="EU-015", article="Art. 17(1)", weight=2, category="conformity",
            question="Is there a documented quality management system covering design, development, testing, and deployment?",
            answer_sources=[_ANNEX_IV, _ATTEST, _SQUASH_CFG],
            answer_cli=["squash annex-iv generate", "squash init"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="EU-016", article="Art. 13(3)(b)", weight=2, category="transparency",
            question="Is the model card accurate, current, and describing the AI system's intended purpose and capabilities?",
            answer_sources=[_MODEL_CARD, _ANNEX_IV],
            answer_cli=["squash model-card --format hf --validate", "squash annex-iv generate"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-017", article="Art. 61(1)", weight=2, category="post-market",
            question="Is a post-market monitoring plan implemented, including systematic collection of performance data?",
            answer_sources=[_DRIFT, _ATTEST, _SCAN],
            answer_cli=["squash drift-check", "squash watch", "squash monitor"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-018", article="Art. 26(1)", weight=2, category="deployer-obligations",
            question="Have deployer obligations been documented, including use-case conformity and human oversight measures?",
            answer_sources=[_ANNEX_IV, _MODEL_CARD],
            answer_cli=["squash annex-iv generate", "squash model-card --format eu-ai-act"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-019", article="Annex IV §1", weight=2, category="technical-documentation",
            question="Does Annex IV §1 describe the AI system's general purpose and intended use with sufficient detail?",
            answer_sources=[_ANNEX_IV],
            answer_cli=["squash annex-iv generate --system-name 'System Name' --intended-purpose '...'"],
            days_to_close=1,
        ),
        ExamQuestion(
            q_id="EU-020", article="Annex IV §2", weight=2, category="technical-documentation",
            question="Are training data, datasets, and data processing methods documented in Annex IV §2?",
            answer_sources=[_ANNEX_IV, _LINEAGE],
            answer_cli=["squash annex-iv generate", "squash data-lineage"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-021", article="Annex IV §3", weight=2, category="technical-documentation",
            question="Is the system architecture, including hardware requirements and model components, documented?",
            answer_sources=[_ANNEX_IV, _BOM],
            answer_cli=["squash annex-iv generate", "squash attest"],
            days_to_close=1,
        ),
        ExamQuestion(
            q_id="EU-022", article="Annex IV §6", weight=2, category="technical-documentation",
            question="Are performance metrics, validation results, and benchmark results documented?",
            answer_sources=[_ANNEX_IV, _ATTEST],
            answer_cli=["squash annex-iv generate", "squash attest --policy eu-ai-act"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-023", article="Art. 9(6)", weight=2, category="risk-management",
            question="Have tests been conducted to identify risk management measures effective for the AI system?",
            answer_sources=[_SCAN, "squash-policy-eu-ai-act.json", _ATTEST],
            answer_cli=["squash attest --policy eu-ai-act", "squash scan ./model"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-024", article="Art. 72(1)", weight=2, category="incident-reporting",
            question="Are logs and incident reports maintained for market surveillance purposes?",
            answer_sources=[_INCIDENT, _ATTEST, _SCAN],
            answer_cli=["squash incident", "squash attest --sign"],
            days_to_close=3,
        ),
        # ── Standard (weight 1) ───────────────────────────────────────────
        ExamQuestion(
            q_id="EU-025", article="Art. 10(6)", weight=1, category="data-governance",
            question="Have measures been taken to detect and address dataset biases across protected attributes?",
            answer_sources=[_BIAS],
            answer_cli=["squash bias-audit --model ./model"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="EU-026", article="Art. 14(4)", weight=1, category="human-oversight",
            question="Do human oversight measures include the ability to halt the AI system in case of anomalous behaviour?",
            answer_sources=[_INCIDENT, _SQUASH_CFG],
            answer_cli=["squash freeze --help", "squash incident"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="EU-027", article="Art. 25(1)", weight=1, category="supply-chain",
            question="Have agreements with distributors and importers of this AI system been documented?",
            answer_sources=[_ATTEST, _BOM],
            answer_cli=["squash attest --sign", "squash trust-package"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="EU-028", article="Art. 53(1)", weight=1, category="gpai",
            question="If this is a general-purpose AI model, has technical documentation per Art. 53 been prepared?",
            answer_sources=[_ANNEX_IV, _BOM, _MODEL_CARD],
            answer_cli=["squash annex-iv generate --format all", "squash model-card --format all"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-029", article="Art. 51(1)", weight=1, category="gpai",
            question="Has a risk classification been performed for the AI system with documented justification?",
            answer_sources=["squash-policy-eu-ai-act.json", _ANNEX_IV],
            answer_cli=["squash attest --policy eu-ai-act", "squash risk-assess"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-030", article="Annex IV §4", weight=1, category="technical-documentation",
            question="Are deployment, operational, and maintenance requirements documented?",
            answer_sources=[_ANNEX_IV],
            answer_cli=["squash annex-iv generate"],
            days_to_close=1,
        ),
        ExamQuestion(
            q_id="EU-031", article="Annex IV §5", weight=1, category="technical-documentation",
            question="Is the risk management process and its outcomes documented per Annex IV §5?",
            answer_sources=[_ANNEX_IV, "squash-policy-eu-ai-act.json"],
            answer_cli=["squash annex-iv generate", "squash attest --policy eu-ai-act"],
            days_to_close=1,
        ),
        ExamQuestion(
            q_id="EU-032", article="Art. 50(1)", weight=1, category="transparency",
            question="Are AI-generated content disclosure mechanisms implemented when required?",
            answer_sources=[_MODEL_CARD, _ANNEX_IV],
            answer_cli=["squash model-card --format eu-ai-act"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-033", article="Art. 9(8)", weight=1, category="risk-management",
            question="Are risk management records kept for at least 10 years after the AI system is placed on the market?",
            answer_sources=[_ATTEST, _ANNEX_IV],
            answer_cli=["squash attest --sign", "squash annual-review"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-034", article="Art. 16(d)", weight=1, category="conformity",
            question="Is there a Declaration of Conformity prepared and signed by the provider?",
            answer_sources=[_ATTEST, "squash-policy-eu-ai-act.json"],
            answer_cli=["squash attest --policy eu-ai-act --sign", "squash trust-package"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="EU-035", article="Art. 16(e)", weight=1, category="conformity",
            question="Has the AI system been registered in the EU AI database as required?",
            answer_sources=[_ATTEST],
            answer_cli=["squash publish --registry eu"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="EU-036", article="Art. 12(2)", weight=1, category="record-keeping",
            question="Are logs collected with sufficient granularity to enable reconstruction of events post-incident?",
            answer_sources=[_ATTEST, _DRIFT],
            answer_cli=["squash watch", "squash drift-check --baseline ./model"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="EU-037", article="Annex IV §7", weight=1, category="technical-documentation",
            question="Are software version control and change management records maintained?",
            answer_sources=[_BOM, _ATTEST],
            answer_cli=["squash attest --sign", "squash diff v1.json v2.json"],
            days_to_close=1,
        ),
        ExamQuestion(
            q_id="EU-038", article="Art. 62(1)", weight=1, category="post-market",
            question="Is there a post-market monitoring plan with defined KPIs for performance and safety?",
            answer_sources=[_DRIFT, _ATTEST],
            answer_cli=["squash monitor", "squash drift-check"],
            days_to_close=3,
        ),
    ]


def _nist_rmf_questions() -> list[ExamQuestion]:
    """30 examiner questions for NIST AI Risk Management Framework 1.0."""
    return [
        # ── GOVERN function ───────────────────────────────────────────────
        ExamQuestion(
            q_id="NIST-G01", article="GOVERN 1.1", weight=3, category="govern",
            question="Are policies, processes, and procedures in place that enable organisational risk management decisions for AI?",
            answer_sources=[_ATTEST, _SQUASH_CFG, "squash-policy-enterprise-strict.json"],
            answer_cli=["squash init", "squash attest --policy enterprise-strict"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-G02", article="GOVERN 1.2", weight=2, category="govern",
            question="Are accountability mechanisms established for AI risk decisions across the organisation?",
            answer_sources=[_ATTEST, _ANNEX_IV],
            answer_cli=["squash attest", "squash annex-iv generate"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-G03", article="GOVERN 1.3", weight=2, category="govern",
            question="Are organisational roles and responsibilities defined for AI risk management?",
            answer_sources=[_ANNEX_IV, _MODEL_CARD],
            answer_cli=["squash annex-iv generate", "squash model-card"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-G04", article="GOVERN 1.4", weight=2, category="govern",
            question="Are teams working on AI systems trained on risk and responsible AI policies?",
            answer_sources=[_SQUASH_CFG, _ATTEST],
            answer_cli=["squash init", "squash install-hook"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="NIST-G05", article="GOVERN 1.5", weight=2, category="govern",
            question="Are processes in place for monitoring and reporting on AI risk management effectiveness?",
            answer_sources=[_DRIFT, _ATTEST, _SCAN],
            answer_cli=["squash drift-check", "squash watch"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-G06", article="GOVERN 1.6", weight=1, category="govern",
            question="Are policies documented for handling AI system failures and incidents?",
            answer_sources=[_INCIDENT, _SQUASH_CFG],
            answer_cli=["squash freeze --help", "squash incident"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="NIST-G07", article="GOVERN 4.1", weight=2, category="govern",
            question="Are third-party AI components and suppliers assessed for risk?",
            answer_sources=[_BOM, _VEX, _SCAN],
            answer_cli=["squash attest", "squash vex update", "squash scan ./model"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-G08", article="GOVERN 6.1", weight=2, category="govern",
            question="Are policies established for managing concentration risk across AI vendors?",
            answer_sources=[_BOM, _ATTEST],
            answer_cli=["squash vendor-registry", "squash attest"],
            days_to_close=5,
        ),
        # ── MAP function ──────────────────────────────────────────────────
        ExamQuestion(
            q_id="NIST-M01", article="MAP 1.1", weight=3, category="map",
            question="Is context established for the AI system including purpose, scope, and stakeholders?",
            answer_sources=[_ANNEX_IV, _MODEL_CARD],
            answer_cli=["squash annex-iv generate", "squash model-card --format all"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-M02", article="MAP 1.5", weight=2, category="map",
            question="Have organisational risk tolerances been established and documented?",
            answer_sources=["squash-policy-enterprise-strict.json", _ANNEX_IV],
            answer_cli=["squash attest --policy enterprise-strict", "squash risk-assess"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-M03", article="MAP 1.6", weight=2, category="map",
            question="Have AI system benefits and potential harms been identified and documented?",
            answer_sources=[_ANNEX_IV, "squash-policy-eu-ai-act.json"],
            answer_cli=["squash risk-assess", "squash annex-iv generate"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-M04", article="MAP 2.1", weight=2, category="map",
            question="Is the scientific basis for the AI model well-understood and documented?",
            answer_sources=[_ANNEX_IV, _MODEL_CARD],
            answer_cli=["squash annex-iv generate", "squash model-card"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-M05", article="MAP 5.1", weight=1, category="map",
            question="Have practices identified in the NIST AI RMF Playbook been reviewed?",
            answer_sources=[_NIST_RMF, _ATTEST],
            answer_cli=["squash attest --policy nist-ai-rmf"],
            days_to_close=5,
        ),
        # ── MEASURE function ──────────────────────────────────────────────
        ExamQuestion(
            q_id="NIST-ME01", article="MEASURE 1.1", weight=3, category="measure",
            question="Are AI risk metrics established and available for testing, monitoring, and evaluation?",
            answer_sources=[_SCAN, _ATTEST, "squash-policy-enterprise-strict.json"],
            answer_cli=["squash attest --policy enterprise-strict", "squash scan ./model"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-ME02", article="MEASURE 2.1", weight=2, category="measure",
            question="Are test sets and evaluation procedures in place to assess AI system performance?",
            answer_sources=[_ATTEST, _SCAN, _ANNEX_IV],
            answer_cli=["squash attest", "squash annex-iv generate"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-ME03", article="MEASURE 2.5", weight=2, category="measure",
            question="Are bias and fairness metrics evaluated and documented?",
            answer_sources=[_BIAS, _ANNEX_IV],
            answer_cli=["squash bias-audit --model ./model"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="NIST-ME04", article="MEASURE 2.6", weight=2, category="measure",
            question="Are AI system outputs evaluated for accuracy and consistency over time?",
            answer_sources=[_DRIFT, _ATTEST],
            answer_cli=["squash drift-check", "squash monitor"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-ME05", article="MEASURE 2.8", weight=2, category="measure",
            question="Are cybersecurity risks to the AI system identified and evaluated?",
            answer_sources=[_SCAN, _VEX],
            answer_cli=["squash scan ./model --exit-2-on-unsafe", "squash vex update"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-ME06", article="MEASURE 2.13", weight=1, category="measure",
            question="Are effects of AI on people and communities evaluated and documented?",
            answer_sources=[_BIAS, _ANNEX_IV],
            answer_cli=["squash bias-audit --model ./model", "squash risk-assess --include-societal"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="NIST-ME07", article="MEASURE 4.1", weight=2, category="measure",
            question="Is risk-measurement data collected to enable feedback on risk management?",
            answer_sources=[_DRIFT, _SCAN, _ATTEST],
            answer_cli=["squash drift-check", "squash watch"],
            days_to_close=2,
        ),
        # ── MANAGE function ───────────────────────────────────────────────
        ExamQuestion(
            q_id="NIST-MA01", article="MANAGE 1.1", weight=3, category="manage",
            question="Are identified AI risks prioritised and managed using established plans?",
            answer_sources=["squash-policy-enterprise-strict.json", _ATTEST],
            answer_cli=["squash attest --policy enterprise-strict", "squash remediate"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-MA02", article="MANAGE 1.3", weight=2, category="manage",
            question="Are responses to AI risks established, documented, and operationalised?",
            answer_sources=[_INCIDENT, _ATTEST],
            answer_cli=["squash incident", "squash freeze --help"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-MA03", article="MANAGE 2.2", weight=2, category="manage",
            question="Are mechanisms in place to monitor and evaluate the effectiveness of risk responses?",
            answer_sources=[_DRIFT, _ATTEST],
            answer_cli=["squash watch", "squash drift-check"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-MA04", article="MANAGE 2.4", weight=2, category="manage",
            question="Are negative impacts and residual risks documented along with treatment decisions?",
            answer_sources=[_ANNEX_IV, _ATTEST],
            answer_cli=["squash risk-assess", "squash annex-iv generate"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-MA05", article="MANAGE 3.1", weight=2, category="manage",
            question="Are AI risk management activities tracked and reported?",
            answer_sources=[_ATTEST, _DRIFT],
            answer_cli=["squash board-report", "squash annual-review"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-MA06", article="MANAGE 3.2", weight=1, category="manage",
            question="Are processes for risk management improvement and learning documented?",
            answer_sources=[_INCIDENT, _ATTEST],
            answer_cli=["squash remediate", "squash annual-review"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-MA07", article="MANAGE 4.1", weight=2, category="manage",
            question="Are AI systems decommissioned or retired based on risk evaluations?",
            answer_sources=[_INCIDENT, _ANNEX_IV],
            answer_cli=["squash freeze", "squash incident"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="NIST-MA08", article="MANAGE 4.2", weight=1, category="manage",
            question="Are lessons learned from AI incidents documented and incorporated into risk management?",
            answer_sources=[_INCIDENT, _DRIFT],
            answer_cli=["squash incident", "squash annual-review"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="NIST-MA09", article="MANAGE 2.1", weight=2, category="manage",
            question="Are treatment options evaluated and selected based on their effectiveness and feasibility?",
            answer_sources=[_ATTEST, "squash-policy-enterprise-strict.json"],
            answer_cli=["squash remediate", "squash attest --policy enterprise-strict"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="NIST-MA10", article="GOVERN 5.1", weight=1, category="manage",
            question="Are AI risk management processes periodically reviewed and updated?",
            answer_sources=[_ATTEST, _DRIFT],
            answer_cli=["squash annual-review", "squash drift-check"],
            days_to_close=3,
        ),
    ]


def _sec_questions() -> list[ExamQuestion]:
    """22 examiner questions for SEC AI disclosure obligations (2026)."""
    return [
        ExamQuestion(
            q_id="SEC-001", article="AI Disclosure §17", weight=3, category="disclosure",
            question="Are material AI risks disclosed in investor filings with specific, not generic, risk language?",
            answer_sources=[_ATTEST, _MODEL_CARD, "squash-policy-eu-ai-act.json"],
            answer_cli=["squash attest", "squash model-card --format all"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="SEC-002", article="OMB M-26-04 §3", weight=3, category="disclosure",
            question="Has a model card and acceptable-use policy been prepared for each AI system used in regulated activities?",
            answer_sources=[_MODEL_CARD, _ANNEX_IV],
            answer_cli=["squash model-card --format all --validate", "squash annex-iv generate"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="SEC-003", article="Investment Adviser Act §204", weight=3, category="compliance",
            question="Are AI-generated investment recommendations subject to human review with documented oversight controls?",
            answer_sources=[_ATTEST, _ANNEX_IV],
            answer_cli=["squash attest --policy eu-ai-act"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="SEC-004", article="AI Claims §11", weight=2, category="disclosure",
            question="Has the organisation verified that public AI capability claims are substantiated by attestation evidence?",
            answer_sources=[_ATTEST, _MODEL_CARD],
            answer_cli=["squash attest --sign", "squash model-card --validate"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="SEC-005", article="Cybersecurity Rule §275", weight=2, category="cybersecurity",
            question="Are AI model security assessments documented and included in cybersecurity disclosures?",
            answer_sources=[_SCAN, _VEX, _ATTEST],
            answer_cli=["squash scan ./model", "squash vex update"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="SEC-006", article="AI Exam Priority §1", weight=2, category="operational",
            question="Are AI systems that influence investment decisions subject to ongoing performance monitoring?",
            answer_sources=[_DRIFT, _ATTEST],
            answer_cli=["squash drift-check", "squash monitor"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="SEC-007", article="Data Governance §15", weight=2, category="data-governance",
            question="Are training data sources for AI models used in investment activities documented?",
            answer_sources=[_LINEAGE, _BOM],
            answer_cli=["squash data-lineage --model ./model"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="SEC-008", article="AI Bias §11(d)", weight=2, category="fairness",
            question="Have AI models been tested for discriminatory outcomes in investment or advisory functions?",
            answer_sources=[_BIAS, _ATTEST],
            answer_cli=["squash bias-audit --model ./model"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="SEC-009", article="Operational Risk §17(a)", weight=2, category="operational",
            question="Are AI model failures and incidents reported to compliance with appropriate escalation procedures?",
            answer_sources=[_INCIDENT, _ATTEST],
            answer_cli=["squash incident", "squash freeze"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="SEC-010", article="Vendor Risk §15(c)", weight=2, category="third-party",
            question="Are third-party AI model providers subject to due diligence including attestation review?",
            answer_sources=[_BOM, _VEX, _SCAN],
            answer_cli=["squash attest", "squash scan ./model", "squash vex update"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="SEC-011", article="Model Risk §SR 11-7", weight=2, category="model-risk",
            question="Is there a model inventory and validation programme covering AI models used in financial decisions?",
            answer_sources=[_ATTEST, _BOM, _DRIFT],
            answer_cli=["squash registry", "squash drift-check"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="SEC-012", article="AI Claims §7(b)", weight=2, category="disclosure",
            question="Are limitations and failure modes of AI systems disclosed to clients?",
            answer_sources=[_MODEL_CARD, _ANNEX_IV],
            answer_cli=["squash model-card --format all"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="SEC-013", article="Record Keeping §204(a)", weight=1, category="record-keeping",
            question="Are records of AI usage in investment decisions retained for the mandated period?",
            answer_sources=[_ATTEST, _DRIFT],
            answer_cli=["squash attest --sign", "squash annual-review"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="SEC-014", article="Conflicts §206(3)", weight=2, category="compliance",
            question="Have conflicts of interest arising from AI use in investment decisions been identified and disclosed?",
            answer_sources=[_ANNEX_IV, _ATTEST],
            answer_cli=["squash risk-assess", "squash annex-iv generate"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="SEC-015", article="AI Exam Priority §3", weight=1, category="operational",
            question="Do compliance policies explicitly address AI use cases within investment operations?",
            answer_sources=[_SQUASH_CFG, "squash-policy-enterprise-strict.json"],
            answer_cli=["squash init", "squash attest --policy enterprise-strict"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="SEC-016", article="OMB M-26-04 §4", weight=2, category="disclosure",
            question="Are AI evaluation artefacts (test results, benchmarks, red-team reports) retained and available for examination?",
            answer_sources=[_ATTEST, _SCAN, _ANNEX_IV],
            answer_cli=["squash attest --sign", "squash annex-iv generate"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="SEC-017", article="AI Wash §17", weight=2, category="disclosure",
            question="Are AI capability claims in marketing materials verified against attestation evidence?",
            answer_sources=[_ATTEST, _MODEL_CARD],
            answer_cli=["squash model-card --validate", "squash attest --sign"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="SEC-018", article="BC/DR §17a-4", weight=1, category="operational",
            question="Is there a business continuity plan for AI system failures affecting investment operations?",
            answer_sources=[_INCIDENT, _SQUASH_CFG],
            answer_cli=["squash freeze --help"],
            days_to_close=10,
        ),
        ExamQuestion(
            q_id="SEC-019", article="Training §204(a)", weight=1, category="operational",
            question="Are staff using AI in investment activities trained on risks, limits, and compliance obligations?",
            answer_sources=[_SQUASH_CFG, _ATTEST],
            answer_cli=["squash init"],
            days_to_close=10,
        ),
        ExamQuestion(
            q_id="SEC-020", article="Audit Trail §17a-4", weight=2, category="record-keeping",
            question="Is there an immutable audit trail for AI model versions and decisions?",
            answer_sources=[_ATTEST, _BOM],
            answer_cli=["squash attest --sign", "squash diff"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="SEC-021", article="Concentration §206", weight=1, category="operational",
            question="Is concentration risk from reliance on a single AI vendor assessed and managed?",
            answer_sources=[_BOM, _ATTEST],
            answer_cli=["squash attest"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="SEC-022", article="Change Mgmt §17(a)", weight=1, category="operational",
            question="Are changes to AI models subject to a validation and approval process before deployment?",
            answer_sources=[_ATTEST, _DRIFT],
            answer_cli=["squash diff", "squash attest", "squash registry-gate --backend mlflow"],
            days_to_close=3,
        ),
    ]


def _fda_questions() -> list[ExamQuestion]:
    """20 examiner questions for FDA AI/ML Software as a Medical Device (SaMD)."""
    return [
        ExamQuestion(
            q_id="FDA-001", article="SaMD Rule §880", weight=3, category="risk-classification",
            question="Has the device software been classified under the correct SaMD risk category (Class I/II/III)?",
            answer_sources=[_ANNEX_IV, _ATTEST],
            answer_cli=["squash annex-iv generate", "squash risk-assess"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="FDA-002", article="510(k) §807", weight=3, category="clearance",
            question="Has the AI/ML system received appropriate FDA clearance or approval, or is it exempt?",
            answer_sources=[_ATTEST, _ANNEX_IV],
            answer_cli=["squash attest --sign", "squash trust-package"],
            days_to_close=30,
        ),
        ExamQuestion(
            q_id="FDA-003", article="SaMD Action Plan §3.1", weight=3, category="clinical-validation",
            question="Has analytical and clinical validation been conducted and documented for the AI/ML algorithm?",
            answer_sources=[_ANNEX_IV, _ATTEST, _BIAS],
            answer_cli=["squash annex-iv generate", "squash bias-audit --model ./model"],
            days_to_close=10,
        ),
        ExamQuestion(
            q_id="FDA-004", article="AI Action Plan §4", weight=2, category="post-market",
            question="Is there a predetermined change control plan (PCCP) for planned AI model modifications?",
            answer_sources=[_DRIFT, _ATTEST, _ANNEX_IV],
            answer_cli=["squash drift-check", "squash watch"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="FDA-005", article="21 CFR Part 820", weight=3, category="quality-system",
            question="Is there a Quality Management System (QMS) covering the AI/ML device development lifecycle?",
            answer_sources=[_ATTEST, _SQUASH_CFG, _BOM],
            answer_cli=["squash init", "squash attest --sign"],
            days_to_close=10,
        ),
        ExamQuestion(
            q_id="FDA-006", article="SaMD §4.3", weight=2, category="clinical-validation",
            question="Are intended use, intended patient population, and clinical context documented?",
            answer_sources=[_ANNEX_IV, _MODEL_CARD],
            answer_cli=["squash annex-iv generate", "squash model-card --format all"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="FDA-007", article="AI Action Plan §2", weight=2, category="transparency",
            question="Is there a labelling strategy that informs users of the AI/ML device's outputs and limitations?",
            answer_sources=[_MODEL_CARD, _ANNEX_IV],
            answer_cli=["squash model-card --format all"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="FDA-008", article="Post-Market §21 CFR 803", weight=2, category="post-market",
            question="Are adverse event reporting procedures in place for AI/ML device malfunctions?",
            answer_sources=[_INCIDENT, _ATTEST],
            answer_cli=["squash incident", "squash freeze"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="FDA-009", article="SaMD §4.4", weight=2, category="data-governance",
            question="Are training and testing datasets documented with source, size, demographics, and preprocessing?",
            answer_sources=[_LINEAGE, _ANNEX_IV, _BIAS],
            answer_cli=["squash data-lineage --model ./model", "squash annex-iv generate"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="FDA-010", article="Fairness §5.1", weight=2, category="fairness",
            question="Has the AI/ML model been evaluated for performance disparities across demographic subgroups?",
            answer_sources=[_BIAS, _ANNEX_IV],
            answer_cli=["squash bias-audit --model ./model"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="FDA-011", article="Cybersecurity §524B", weight=2, category="cybersecurity",
            question="Has a cybersecurity risk assessment been conducted and documented for the AI/ML device?",
            answer_sources=[_SCAN, _VEX],
            answer_cli=["squash scan ./model --exit-2-on-unsafe", "squash vex update"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="FDA-012", article="SaMD §3.2", weight=2, category="quality-system",
            question="Is there a software version control and configuration management process?",
            answer_sources=[_BOM, _ATTEST],
            answer_cli=["squash attest --sign", "squash diff v1.json v2.json"],
            days_to_close=2,
        ),
        ExamQuestion(
            q_id="FDA-013", article="AI Action Plan §3.2", weight=2, category="post-market",
            question="Is real-world performance data collected and analysed for ongoing monitoring?",
            answer_sources=[_DRIFT, _ATTEST],
            answer_cli=["squash drift-check", "squash monitor"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="FDA-014", article="SaMD §5.1", weight=1, category="risk-classification",
            question="Are failure mode analyses (FMEA/FMECA) documented for the AI/ML algorithm?",
            answer_sources=[_ANNEX_IV, _SCAN],
            answer_cli=["squash risk-assess", "squash scan ./model"],
            days_to_close=10,
        ),
        ExamQuestion(
            q_id="FDA-015", article="21 CFR Part 11", weight=1, category="record-keeping",
            question="Do electronic records meet 21 CFR Part 11 requirements for integrity and audit trail?",
            answer_sources=[_ATTEST, _BOM],
            answer_cli=["squash attest --sign"],
            days_to_close=5,
        ),
        ExamQuestion(
            q_id="FDA-016", article="Labelling §801", weight=1, category="transparency",
            question="Does device labelling include sufficient information for safe and effective use?",
            answer_sources=[_MODEL_CARD, _ANNEX_IV],
            answer_cli=["squash model-card --format all"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="FDA-017", article="Human Factors §11937", weight=2, category="usability",
            question="Has user interface validation been conducted to ensure safe human-device interaction?",
            answer_sources=[_ANNEX_IV],
            answer_cli=["squash annex-iv generate"],
            days_to_close=10,
        ),
        ExamQuestion(
            q_id="FDA-018", article="SaMD §6", weight=1, category="supply-chain",
            question="Are software component supply-chain risks documented and managed?",
            answer_sources=[_BOM, _VEX],
            answer_cli=["squash attest", "squash vex update"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="FDA-019", article="AI Action Plan §5", weight=1, category="transparency",
            question="Is transparency information about the AI model's training and capabilities publicly available?",
            answer_sources=[_MODEL_CARD, _ANNEX_IV],
            answer_cli=["squash model-card --format all --push-to-hub user/model"],
            days_to_close=3,
        ),
        ExamQuestion(
            q_id="FDA-020", article="AI Action Plan §1", weight=2, category="post-market",
            question="Has the organisation engaged with FDA's Digital Health Center of Excellence for guidance?",
            answer_sources=[_ATTEST, _ANNEX_IV],
            answer_cli=["squash attest --sign"],
            days_to_close=30,
        ),
    ]


__all__ = [
    "ExamQuestion",
    "ExamAnswer",
    "ReadinessReport",
    "AuditSimulator",
    "SUPPORTED_REGULATORS",
]

SUPPORTED_REGULATORS = AuditSimulator.SUPPORTED_REGULATORS
