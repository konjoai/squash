"""squash/procurement_scoring.py — Track D / D3 — AI Procurement Scoring API.

Sprint 28 (W246–W248).

Every Fortune 500 procurement team is now writing AI vendor questionnaires.
They take 4 weeks each. Squash already has Trust Packages (W171). Sprint 28
turns the trust package into a queryable API — the credit-score equivalent
for AI compliance.

Public endpoint:  GET api.squash.works/v1/score/{vendor}
Freemium model:
  Free / unauthenticated  → score + tier + last_attested + frameworks + badge_url
  Pro                     → + breakdown (per-framework scores)
  Enterprise              → + breakdown + history (12-month time series) +
                             real-time webhook on vendor.score_changed

Network effect: more vendors publish Trust Packages → more buyers query the API →
more vendors want to be visible → more attestations enter the registry. The SSL
certificate authority play for AI compliance.

Scoring algorithm
-----------------
Five components, each 0–100, combined with empirically-weighted coefficients:

  component              weight  derivation
  ─────────────────────  ──────  ──────────────────────────────────────────
  compliance_score         0.40  avg(compliance_score) across active attestations
                                  from attestation_registry; 0 if no entries
  freshness                0.20  decay function on days since most-recent attestation
                                  (100 at day 0, 50 at day 30, ~0 at day 90)
  framework_coverage       0.20  len(unique frameworks) / MAX_FRAMEWORKS (capped at 8)
  attestation_frequency    0.10  min(1.0, attestations_last_30d / FREQ_TARGET) × 100
  trust_package            0.10  100 if vendor has a verified Trust Package, else 0

Tier assignment:
  CERTIFIED    score ≥ 90  — all five components strong, recent
  VERIFIED     score ≥ 75
  BASIC        score ≥ 50
  UNVERIFIED   score < 50 or no attestations
"""

from __future__ import annotations

import datetime
import hashlib
import html
import math
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VERSION = "0.1.0"

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_FRAMEWORKS   = 8     # normalisation cap for framework_coverage component
FREQ_TARGET      = 4     # attestations/30d considered "fully frequent"
FRESHNESS_HALF   = 30.0  # days at which freshness score = 50
CERTIFIED_THRESH = 90.0
VERIFIED_THRESH  = 75.0
BASIC_THRESH     = 50.0

_WEIGHTS = {
    "compliance_score":     0.40,
    "freshness":            0.20,
    "framework_coverage":   0.20,
    "attestation_frequency":0.10,
    "trust_package":        0.10,
}

# Tier colours for badge SVG (hex, shields.io palette)
_TIER_COLOUR = {
    "CERTIFIED":  "#22c55e",   # brand green
    "VERIFIED":   "#3b82f6",   # blue
    "BASIC":      "#f59e0b",   # amber
    "UNVERIFIED": "#6b7280",   # grey
}


# ── Data model ─────────────────────────────────────────────────────────────────


@dataclass
class ComponentScores:
    compliance_score:      float   # 0–100
    freshness:             float
    framework_coverage:    float
    attestation_frequency: float
    trust_package:         float

    def weighted_total(self) -> float:
        return sum(
            getattr(self, k) * w for k, w in _WEIGHTS.items()
        )

    def to_dict(self) -> dict[str, float]:
        return {k: round(getattr(self, k), 2) for k in _WEIGHTS}


@dataclass
class VendorScore:
    """Full procurement score for one vendor."""

    vendor: str
    score: float               # 0–100, rounded to 1 decimal
    tier: str                  # CERTIFIED | VERIFIED | BASIC | UNVERIFIED
    last_attested: str | None  # ISO-8601 UTC or None
    frameworks: list[str]
    attestation_count: int
    has_trust_package: bool
    badge_url: str
    computed_at: str
    squash_version: str = VERSION

    # Free tier stops here ────────────────────────────────────────────────────
    # Pro+ fields (None when not unlocked)
    breakdown: ComponentScores | None = None

    # Enterprise+ fields (None when not unlocked)
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self, include_breakdown: bool = False,
                include_history: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "vendor":             self.vendor,
            "score":              self.score,
            "tier":               self.tier,
            "last_attested":      self.last_attested,
            "frameworks":         self.frameworks,
            "attestation_count":  self.attestation_count,
            "has_trust_package":  self.has_trust_package,
            "badge_url":          self.badge_url,
            "computed_at":        self.computed_at,
            "squash_version":     self.squash_version,
        }
        if include_breakdown and self.breakdown:
            d["breakdown"] = self.breakdown.to_dict()
        if include_history and self.history:
            d["history"] = self.history
        return d


# ── Scoring engine ─────────────────────────────────────────────────────────────


class ProcurementScorer:
    """Compute vendor compliance scores from the local registry databases.

    Both `AttestationRegistry` and `VendorRegistry` are optional —
    if absent the scorer returns a zero-evidence UNVERIFIED result so
    the API can always respond rather than erroring.
    """

    def __init__(
        self,
        attestation_db: Path | None = None,
        vendor_db: Path | None = None,
        base_url: str = "https://squash.works",
    ) -> None:
        self._att_db   = attestation_db
        self._vend_db  = vendor_db
        self._base_url = base_url.rstrip("/")

    # ── Public interface ───────────────────────────────────────────────────────

    def score_vendor(self, vendor: str) -> VendorScore:
        """Compute the current score for *vendor*.

        Pulls all attestation entries matching the vendor name from
        `AttestationRegistry` and checks for a verified Trust Package
        in `VendorRegistry`. Falls back gracefully if either DB is
        unavailable or empty.
        """
        now = _utc_now()
        entries = self._fetch_attestation_entries(vendor)
        trust_pkg = self._has_trust_package(vendor)

        components = self._compute_components(entries, trust_pkg, now)
        raw_score  = components.weighted_total()
        score      = round(max(0.0, min(100.0, raw_score)), 1)
        tier       = _assign_tier(score, len(entries))

        last_att   = _most_recent(entries)
        frameworks = sorted({fw for e in entries for fw in e.get("frameworks", [])})

        return VendorScore(
            vendor            = vendor,
            score             = score,
            tier              = tier,
            last_attested     = last_att,
            frameworks        = frameworks,
            attestation_count = len(entries),
            has_trust_package = trust_pkg,
            badge_url         = f"{self._base_url}/v1/score/{vendor}/badge",
            computed_at       = now,
            breakdown         = components,  # caller decides whether to expose
        )

    def score_history(
        self,
        vendor: str,
        months: int = 12,
    ) -> list[dict[str, Any]]:
        """Return a monthly time-series of scores for *vendor*.

        Reconstructs approximate historical scores by sampling the
        attestation entries published each calendar month and scoring
        only those entries visible at that snapshot date.
        """
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        result: list[dict[str, Any]] = []

        all_entries = self._fetch_attestation_entries(vendor)
        trust_pkg   = self._has_trust_package(vendor)

        for m in range(months, 0, -1):
            snap_dt = now_dt - datetime.timedelta(days=30 * m)
            snap_str = snap_dt.isoformat(timespec="seconds")

            # Only entries published at or before the snapshot date
            visible = [
                e for e in all_entries
                if (e.get("published_at") or "") <= snap_str
            ]
            comps = self._compute_components(visible, trust_pkg, snap_str)
            score = round(max(0.0, min(100.0, comps.weighted_total())), 1)

            result.append({
                "month":  snap_dt.strftime("%Y-%m"),
                "score":  score,
                "tier":   _assign_tier(score, len(visible)),
                "count":  len(visible),
            })

        return result

    def badge_svg(self, vendor: str, score: float, tier: str) -> str:
        """Return an embeddable shields.io-style badge SVG for *vendor*."""
        colour    = _TIER_COLOUR.get(tier, _TIER_COLOUR["UNVERIFIED"])
        label     = html.escape("squash score")
        value     = html.escape(f"{score:.0f} · {tier}")
        label_w   = 100
        value_w   = 110
        total_w   = label_w + value_w
        label_x   = label_w // 2
        value_x   = label_w + value_w // 2
        return f"""<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{total_w}" height="20" role="img" aria-label="{label}: {value}">
  <title>{label}: {value}</title>
  <linearGradient id="sg" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="sr"><rect width="{total_w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#sr)">
    <rect width="{label_w}" height="20" fill="#555"/>
    <rect x="{label_w}" width="{value_w}" height="20" fill="{colour}"/>
    <rect width="{total_w}" height="20" fill="url(#sg)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="{label_x * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(label_w - 10) * 10}" lengthAdjust="spacing">{label}</text>
    <text x="{label_x * 10}" y="140" transform="scale(.1)" textLength="{(label_w - 10) * 10}" lengthAdjust="spacing">{label}</text>
    <text x="{value_x * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(value_w - 10) * 10}" lengthAdjust="spacing">{value}</text>
    <text x="{value_x * 10}" y="140" transform="scale(.1)" textLength="{(value_w - 10) * 10}" lengthAdjust="spacing">{value}</text>
  </g>
</svg>"""

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _fetch_attestation_entries(self, vendor: str) -> list[dict[str, Any]]:
        """Pull attestation entries for *vendor* from AttestationRegistry."""
        try:
            from squash.attestation_registry import AttestationRegistry
            db_kw = {"db_path": self._att_db} if self._att_db else {}
            with AttestationRegistry(**db_kw) as reg:
                all_entries = reg.list(limit=500) if hasattr(reg, "list") else []
                if not all_entries:
                    # Fallback: scan SQLite directly
                    all_entries = self._sqlite_scan_attestations(vendor)
                return [
                    e.to_dict() if hasattr(e, "to_dict") else e
                    for e in all_entries
                    if _vendor_match(
                        (e.to_dict() if hasattr(e, "to_dict") else e).get("org", ""),
                        vendor,
                    ) or _vendor_match(
                        (e.to_dict() if hasattr(e, "to_dict") else e).get("model_id", ""),
                        vendor,
                    )
                ]
        except Exception:  # noqa: BLE001
            return self._sqlite_scan_attestations(vendor)

    def _sqlite_scan_attestations(self, vendor: str) -> list[dict[str, Any]]:
        """Direct SQLite scan — used when AttestationRegistry.list() is absent."""
        db_path = self._att_db or (Path.home() / ".squash" / "attestation_registry.db")
        if not Path(db_path).exists():
            return []
        try:
            conn = sqlite3.connect(str(db_path))
            rows = conn.execute(
                "SELECT entry_id, org, model_id, published_at, frameworks, "
                "compliance_score, revoked FROM attestations WHERE revoked=0 "
                "LIMIT 500"
            ).fetchall()
            conn.close()
        except Exception:  # noqa: BLE001
            return []

        result = []
        for row in rows:
            entry_id, org, model_id, published_at, fws_raw, score, revoked = row
            if not (_vendor_match(org, vendor) or _vendor_match(model_id, vendor)):
                continue
            try:
                fws = fws_raw.split(",") if fws_raw else []
            except AttributeError:
                fws = []
            result.append({
                "entry_id": entry_id,
                "org": org,
                "model_id": model_id,
                "published_at": published_at or "",
                "frameworks": fws,
                "compliance_score": score,
                "revoked": bool(revoked),
            })
        return result

    def _has_trust_package(self, vendor: str) -> bool:
        """Check if *vendor* has a verified Trust Package in VendorRegistry."""
        try:
            from squash.vendor_registry import VendorRegistry
            db_kw = {"db_path": self._vend_db} if self._vend_db else {}
            reg = VendorRegistry(**db_kw)
            vendors = reg.list_vendors()
            for v in vendors:
                vd = v.to_dict() if hasattr(v, "to_dict") else v
                if _vendor_match(vd.get("name", ""), vendor):
                    return bool(vd.get("trust_package_verified"))
        except Exception:  # noqa: BLE001
            pass
        return False

    def _compute_components(
        self,
        entries: list[dict[str, Any]],
        trust_pkg: bool,
        now: str,
    ) -> ComponentScores:
        if not entries:
            return ComponentScores(0, 0, 0, 0, 100.0 if trust_pkg else 0.0)

        # 1. Compliance score — average of non-None attestation scores
        scores = [
            float(e["compliance_score"])
            for e in entries
            if e.get("compliance_score") is not None
        ]
        compliance = (sum(scores) / len(scores) * 100) if scores else 0.0
        # compliance_score is stored 0–1; multiply by 100
        if scores and max(scores) <= 1.0:
            compliance = (sum(scores) / len(scores)) * 100

        # 2. Freshness — exponential decay based on days since last attestation
        last = _most_recent(entries)
        if last:
            try:
                last_dt = datetime.datetime.fromisoformat(last)
                now_dt  = datetime.datetime.fromisoformat(now)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=datetime.timezone.utc)
                if now_dt.tzinfo is None:
                    now_dt = now_dt.replace(tzinfo=datetime.timezone.utc)
                age_days = max(0, (now_dt - last_dt).days)
                freshness = 100.0 * math.exp(-age_days * math.log(2) / FRESHNESS_HALF)
            except (ValueError, TypeError):
                freshness = 0.0
        else:
            freshness = 0.0

        # 3. Framework coverage
        fws = {fw for e in entries for fw in e.get("frameworks", [])}
        coverage = min(100.0, len(fws) / MAX_FRAMEWORKS * 100)

        # 4. Attestation frequency (last 30 days)
        now_dt2 = datetime.datetime.fromisoformat(now)
        if now_dt2.tzinfo is None:
            now_dt2 = now_dt2.replace(tzinfo=datetime.timezone.utc)
        recent = sum(
            1 for e in entries
            if _within_days(e.get("published_at", ""), 30, now_dt2)
        )
        frequency = min(100.0, (recent / FREQ_TARGET) * 100)

        # 5. Trust package
        trust = 100.0 if trust_pkg else 0.0

        return ComponentScores(
            compliance_score=round(compliance, 2),
            freshness=round(freshness, 2),
            framework_coverage=round(coverage, 2),
            attestation_frequency=round(frequency, 2),
            trust_package=trust,
        )


# ── Helpers ────────────────────────────────────────────────────────────────────


def _assign_tier(score: float, entry_count: int) -> str:
    if entry_count == 0:
        return "UNVERIFIED"
    if score >= CERTIFIED_THRESH:
        return "CERTIFIED"
    if score >= VERIFIED_THRESH:
        return "VERIFIED"
    if score >= BASIC_THRESH:
        return "BASIC"
    return "UNVERIFIED"


def _vendor_match(candidate: str, vendor: str) -> bool:
    """Loose case-insensitive match between a vendor name and a stored string."""
    if not candidate or not vendor:
        return False
    c, v = candidate.lower(), vendor.lower()
    return c == v or c.startswith(v) or v.startswith(c) or v in c or c in v


def _most_recent(entries: list[dict[str, Any]]) -> str | None:
    dates = [e.get("published_at", "") for e in entries if e.get("published_at")]
    return max(dates) if dates else None


def _within_days(
    iso_str: str,
    days: int,
    now_dt: datetime.datetime,
) -> bool:
    if not iso_str:
        return False
    try:
        dt = datetime.datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return (now_dt - dt).days <= days
    except ValueError:
        return False


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
