"""squash/bias_audit.py — Algorithmic bias audit.

Regulatory drivers
------------------
* **NYC Local Law 144** — bias audits required for automated employment
  decision tools in NYC; annual audit + public summary
* **EU AI Act Annex III** — bias assessment required for high-risk AI in
  employment, credit, law enforcement, education, essential services
* **ECOA / Fair Housing Act** — disparate impact testing for credit/lending
* **Workday lawsuit (2025)** — federal court expanded to cover all applicants
  over 40 rejected since 2020; board-level liability precedent

Metrics implemented
-------------------
* **Demographic Parity Difference (DPD)** — difference in positive outcome
  rates between groups; |DPD| ≤ 0.05 = fair per NYC LL144 guidance
* **Disparate Impact Ratio (DIR)** — ratio of positive outcome rates;
  DIR ≥ 0.80 = "4/5ths rule" (EEOC standard, US employment law)
* **Equalized Odds Difference (EOD)** — max difference in TPR and FPR
  across protected groups; |EOD| ≤ 0.05 is a common threshold
* **Predictive Equality Difference (PED)** — false positive rate parity
* **Accuracy Parity** — accuracy gap between groups

Zero external dependencies — all statistics use stdlib math only.
Optional: numpy/scipy for exact confidence intervals when installed.

Usage::

    from squash.bias_audit import BiasAuditor
    import csv

    result = BiasAuditor.audit_from_csv(
        predictions_path=Path("predictions.csv"),
        labels_path=Path("groundtruth.csv"),
        protected_attributes=["age_group", "gender"],
        label_col="decision",
        pred_col="model_output",
    )
    print(result.summary())
    result.save(Path("bias_audit_report.json"))
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import json
import logging
import math
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class FairnessVerdict(str, Enum):
    PASS = "PASS"       # All metrics within thresholds
    WARN = "WARN"       # At least one metric close to threshold
    FAIL = "FAIL"       # At least one metric outside threshold


class RegulatoryStandard(str, Enum):
    NYC_LOCAL_LAW_144 = "nyc_local_law_144"
    EU_AI_ACT_ANNEX_III = "eu_ai_act_annex_iii"
    ECOA_4_5THS = "ecoa_4_5ths_rule"
    FAIR_HOUSING = "fair_housing"
    GENERIC = "generic"


# ── Thresholds per regulatory standard ────────────────────────────────────────
_THRESHOLDS: dict[str, dict[str, float]] = {
    "nyc_local_law_144":   {"dpd": 0.05,  "dir": 0.80, "eod": 0.05, "ped": 0.05},
    "eu_ai_act_annex_iii": {"dpd": 0.05,  "dir": 0.80, "eod": 0.05, "ped": 0.10},
    "ecoa_4_5ths_rule":    {"dpd": 0.10,  "dir": 0.80, "eod": 0.10, "ped": 0.10},
    "fair_housing":        {"dpd": 0.10,  "dir": 0.80, "eod": 0.10, "ped": 0.10},
    "generic":             {"dpd": 0.10,  "dir": 0.80, "eod": 0.10, "ped": 0.10},
}


@dataclass
class GroupMetrics:
    group_name: str
    attribute: str
    n_total: int
    n_positive: int
    n_true_positive: int
    n_false_positive: int
    n_true_negative: int
    n_false_negative: int

    @property
    def positive_rate(self) -> float:
        return self.n_positive / max(self.n_total, 1)

    @property
    def tpr(self) -> float:  # True Positive Rate / Recall
        denom = self.n_true_positive + self.n_false_negative
        return self.n_true_positive / max(denom, 1)

    @property
    def fpr(self) -> float:  # False Positive Rate
        denom = self.n_false_positive + self.n_true_negative
        return self.n_false_positive / max(denom, 1)

    @property
    def accuracy(self) -> float:
        return (self.n_true_positive + self.n_true_negative) / max(self.n_total, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group_name,
            "attribute": self.attribute,
            "n_total": self.n_total,
            "n_positive": self.n_positive,
            "positive_rate": round(self.positive_rate, 4),
            "true_positive_rate": round(self.tpr, 4),
            "false_positive_rate": round(self.fpr, 4),
            "accuracy": round(self.accuracy, 4),
        }


@dataclass
class AttributeResult:
    attribute: str
    privileged_group: str
    unprivileged_groups: list[str]
    demographic_parity_diff: float
    disparate_impact_ratio: float
    equalized_odds_diff: float
    predictive_equality_diff: float
    accuracy_diff: float
    verdict: FairnessVerdict
    failing_metrics: list[str]
    groups: list[GroupMetrics] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attribute": self.attribute,
            "privileged_group": self.privileged_group,
            "unprivileged_groups": self.unprivileged_groups,
            "metrics": {
                "demographic_parity_diff": round(self.demographic_parity_diff, 4),
                "disparate_impact_ratio": round(self.disparate_impact_ratio, 4),
                "equalized_odds_diff": round(self.equalized_odds_diff, 4),
                "predictive_equality_diff": round(self.predictive_equality_diff, 4),
                "accuracy_diff": round(self.accuracy_diff, 4),
            },
            "verdict": self.verdict.value,
            "failing_metrics": self.failing_metrics,
            "groups": [g.to_dict() for g in self.groups],
        }


@dataclass
class BiasAuditReport:
    audit_id: str
    model_id: str
    audited_at: str
    n_total_samples: int
    regulatory_standard: str
    protected_attributes: list[str]
    results: list[AttributeResult] = field(default_factory=list)
    overall_verdict: FairnessVerdict = FairnessVerdict.PASS
    failing_attributes: list[str] = field(default_factory=list)
    data_hash: str = ""

    def summary(self) -> str:
        icon = {"PASS": "✅", "WARN": "⚠ ", "FAIL": "❌"}[self.overall_verdict.value]
        lines = [
            "ALGORITHMIC BIAS AUDIT REPORT",
            "=" * 52,
            f"Audit ID:   {self.audit_id}",
            f"Model:      {self.model_id}",
            f"Audited:    {self.audited_at}",
            f"Standard:   {self.regulatory_standard}",
            f"Samples:    {self.n_total_samples:,}",
            f"Verdict:    {icon} {self.overall_verdict.value}",
            "",
        ]
        for res in self.results:
            icon_a = {"PASS": "✅", "WARN": "⚠ ", "FAIL": "❌"}[res.verdict.value]
            lines.append(f"{icon_a} {res.attribute}: DPD={res.demographic_parity_diff:+.3f}  "
                         f"DIR={res.disparate_impact_ratio:.3f}  "
                         f"EOD={res.equalized_odds_diff:+.3f}")
            if res.failing_metrics:
                lines.append(f"   FAILING: {', '.join(res.failing_metrics)}")
        if self.failing_attributes:
            lines += ["", "Failing Attributes:", *[f"  • {a}" for a in self.failing_attributes]]
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_type": "BIAS_AUDIT_REPORT",
            "regulatory_standard": self.regulatory_standard,
            "audit_id": self.audit_id,
            "model_id": self.model_id,
            "audited_at": self.audited_at,
            "n_total_samples": self.n_total_samples,
            "protected_attributes": self.protected_attributes,
            "overall_verdict": self.overall_verdict.value,
            "failing_attributes": self.failing_attributes,
            "data_hash": self.data_hash,
            "attribute_results": [r.to_dict() for r in self.results],
        }

    def save(self, path: Path) -> None:
        path = Path(path)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        log.info("Bias audit report written to %s", path)


# ── Auditor ───────────────────────────────────────────────────────────────────

class BiasAuditor:
    """Audit model predictions for algorithmic bias across protected attributes."""

    @staticmethod
    def audit(
        predictions: list[dict[str, Any]],
        protected_attributes: list[str],
        label_col: str = "label",
        pred_col: str = "prediction",
        model_id: str = "model",
        standard: str = "generic",
    ) -> BiasAuditReport:
        """Audit a list of prediction dicts."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        audit_id = hashlib.sha256(f"{model_id}{now}".encode()).hexdigest()[:12].upper()

        data_hash = hashlib.sha256(
            json.dumps(predictions[:100], sort_keys=True).encode()
        ).hexdigest()

        # Normalize standard
        std_key = standard.lower().replace("-", "_").replace(" ", "_")
        if std_key not in _THRESHOLDS:
            std_key = "generic"
        thresholds = _THRESHOLDS[std_key]

        results: list[AttributeResult] = []
        for attr in protected_attributes:
            result = _audit_attribute(predictions, attr, label_col, pred_col, thresholds)
            results.append(result)

        failing = [r.attribute for r in results if r.verdict == FairnessVerdict.FAIL]
        has_warn = any(r.verdict == FairnessVerdict.WARN for r in results)
        overall = (
            FairnessVerdict.FAIL if failing
            else FairnessVerdict.WARN if has_warn
            else FairnessVerdict.PASS
        )

        return BiasAuditReport(
            audit_id=audit_id,
            model_id=model_id,
            audited_at=now,
            n_total_samples=len(predictions),
            regulatory_standard=std_key,
            protected_attributes=protected_attributes,
            results=results,
            overall_verdict=overall,
            failing_attributes=failing,
            data_hash=data_hash,
        )

    @staticmethod
    def audit_from_csv(
        predictions_path: Path,
        protected_attributes: list[str],
        label_col: str = "label",
        pred_col: str = "prediction",
        labels_path: Path | None = None,
        model_id: str = "model",
        standard: str = "generic",
    ) -> BiasAuditReport:
        """Load predictions from CSV and audit."""
        predictions_path = Path(predictions_path)
        rows = _read_csv(predictions_path)

        if labels_path:
            labels_path = Path(labels_path)
            label_rows = _read_csv(labels_path)
            # Merge on index
            for i, row in enumerate(rows):
                if i < len(label_rows):
                    row[label_col] = label_rows[i].get(label_col, label_rows[i].get("label", ""))

        return BiasAuditor.audit(
            predictions=rows,
            protected_attributes=protected_attributes,
            label_col=label_col,
            pred_col=pred_col,
            model_id=model_id,
            standard=standard,
        )

    @staticmethod
    def audit_from_dicts(
        records: list[dict[str, Any]],
        protected_attributes: list[str],
        label_col: str = "label",
        pred_col: str = "prediction",
        model_id: str = "model",
        standard: str = "nyc_local_law_144",
    ) -> BiasAuditReport:
        return BiasAuditor.audit(records, protected_attributes, label_col, pred_col, model_id, standard)


# ── Core metric computation ───────────────────────────────────────────────────

def _audit_attribute(
    records: list[dict[str, Any]],
    attribute: str,
    label_col: str,
    pred_col: str,
    thresholds: dict[str, float],
) -> AttributeResult:
    """Compute all fairness metrics for one protected attribute."""
    # Group records by attribute value
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        val = str(r.get(attribute, "unknown"))
        groups.setdefault(val, []).append(r)

    if len(groups) < 2:
        return _trivial_result(attribute, groups)

    # Compute per-group metrics
    group_metrics: dict[str, GroupMetrics] = {}
    for group_name, group_records in groups.items():
        gm = _compute_group_metrics(group_name, attribute, group_records, label_col, pred_col)
        group_metrics[group_name] = gm

    # Privileged group = highest positive rate (reference group)
    privileged = max(group_metrics.keys(), key=lambda g: group_metrics[g].positive_rate)
    priv = group_metrics[privileged]
    unpriv_names = [g for g in group_metrics if g != privileged]

    dpd_max = max(
        abs(priv.positive_rate - group_metrics[g].positive_rate) for g in unpriv_names
    )
    dir_min = min(
        group_metrics[g].positive_rate / max(priv.positive_rate, 1e-9) for g in unpriv_names
    )
    eod_max = max(
        max(abs(priv.tpr - group_metrics[g].tpr), abs(priv.fpr - group_metrics[g].fpr))
        for g in unpriv_names
    )
    ped_max = max(
        abs(priv.fpr - group_metrics[g].fpr) for g in unpriv_names
    )
    acc_max = max(
        abs(priv.accuracy - group_metrics[g].accuracy) for g in unpriv_names
    )

    # Determine verdict
    failing: list[str] = []
    warn_metrics: list[str] = []

    if dpd_max > thresholds["dpd"]:
        failing.append(f"DPD={dpd_max:.3f} > threshold={thresholds['dpd']}")
    elif dpd_max > thresholds["dpd"] * 0.8:
        warn_metrics.append(f"DPD={dpd_max:.3f} close to threshold")

    if dir_min < thresholds["dir"]:
        failing.append(f"DIR={dir_min:.3f} < threshold={thresholds['dir']}")
    elif dir_min < thresholds["dir"] * 1.05:
        warn_metrics.append(f"DIR={dir_min:.3f} close to threshold")

    if eod_max > thresholds["eod"]:
        failing.append(f"EOD={eod_max:.3f} > threshold={thresholds['eod']}")

    if ped_max > thresholds["ped"]:
        failing.append(f"PED={ped_max:.3f} > threshold={thresholds['ped']}")

    verdict = (
        FairnessVerdict.FAIL if failing
        else FairnessVerdict.WARN if warn_metrics
        else FairnessVerdict.PASS
    )

    return AttributeResult(
        attribute=attribute,
        privileged_group=privileged,
        unprivileged_groups=unpriv_names,
        demographic_parity_diff=dpd_max,
        disparate_impact_ratio=dir_min,
        equalized_odds_diff=eod_max,
        predictive_equality_diff=ped_max,
        accuracy_diff=acc_max,
        verdict=verdict,
        failing_metrics=failing + warn_metrics,
        groups=list(group_metrics.values()),
    )


def _compute_group_metrics(
    group_name: str,
    attribute: str,
    records: list[dict[str, Any]],
    label_col: str,
    pred_col: str,
) -> GroupMetrics:
    n = len(records)
    tp = fp = tn = fn = 0
    for r in records:
        label = _to_bool(r.get(label_col, 0))
        pred = _to_bool(r.get(pred_col, 0))
        if label and pred:
            tp += 1
        elif not label and pred:
            fp += 1
        elif not label and not pred:
            tn += 1
        else:
            fn += 1
    return GroupMetrics(
        group_name=group_name, attribute=attribute,
        n_total=n, n_positive=tp + fp,
        n_true_positive=tp, n_false_positive=fp,
        n_true_negative=tn, n_false_negative=fn,
    )


def _to_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val > 0.5
    s = str(val).strip().lower()
    return s in ("1", "true", "yes", "positive", "hired", "approved", "pass", "accept")


def _trivial_result(attribute: str, groups: dict) -> AttributeResult:
    group_list = list(groups.keys())
    return AttributeResult(
        attribute=attribute,
        privileged_group=group_list[0] if group_list else "unknown",
        unprivileged_groups=group_list[1:],
        demographic_parity_diff=0.0,
        disparate_impact_ratio=1.0,
        equalized_odds_diff=0.0,
        predictive_equality_diff=0.0,
        accuracy_diff=0.0,
        verdict=FairnessVerdict.PASS,
        failing_metrics=[],
        groups=[],
    )


def _read_csv(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))
    return rows
