"""squash/metrics.py — Prometheus-compatible metrics collector.

Emits counters and gauges in the Prometheus text exposition format for
the ``GET /metrics`` endpoint, enabling Grafana, Prometheus, Datadog, and
any OpenMetrics-compatible backend to scrape squash runtime data.

Tracked metrics
---------------
``squash_attestations_total``         — Counter by result (passed/failed) and policy.
``squash_policy_violations_total``    — Counter by policy name.
``squash_drift_events_total``         — Counter of drift detection events.
``squash_models_compliant_ratio``     — Gauge: compliant attestations / total.
``squash_quota_used_total``           — Counter: total quota consumed across all keys.
``squash_api_requests_total``         — Counter by endpoint and status code.
``squash_api_latency_seconds``        — Summary of response latencies by endpoint.

Usage::

    from squash.metrics import MetricsCollector, get_collector

    collector = get_collector()
    collector.inc_attestation(passed=True, policy="eu-ai-act")
    collector.inc_violation(policy="eu-ai-act")

    # Get Prometheus text format
    text = collector.render()

    # In FastAPI (wired in api.py):
    @app.get("/metrics")
    async def metrics():
        return PlainTextResponse(get_collector().render(), media_type="text/plain; version=0.0.4")
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


# ── Metric primitives ──────────────────────────────────────────────────────────


class Counter:
    """Thread-safe monotonically increasing counter."""

    def __init__(self, name: str, help_text: str, labels: tuple[str, ...] = ()) -> None:
        self.name = name
        self.help_text = help_text
        self.labels = labels
        self._values: dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def inc(self, value: float = 1.0, **label_values: str) -> None:
        key = tuple(label_values.get(lbl, "") for lbl in self.labels)
        with self._lock:
            self._values[key] += value

    def get(self, **label_values: str) -> float:
        key = tuple(label_values.get(lbl, "") for lbl in self.labels)
        with self._lock:
            return self._values[key]

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} counter",
        ]
        with self._lock:
            items = list(self._values.items())
        for key, value in items:
            label_str = _fmt_labels(self.labels, key)
            lines.append(f"{self.name}{label_str} {value}")
        if not items:
            lines.append(f"{self.name} 0")
        return "\n".join(lines)

    def reset(self) -> None:
        with self._lock:
            self._values.clear()


class Gauge:
    """Thread-safe gauge (can go up and down)."""

    def __init__(self, name: str, help_text: str, labels: tuple[str, ...] = ()) -> None:
        self.name = name
        self.help_text = help_text
        self.labels = labels
        self._values: dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def set(self, value: float, **label_values: str) -> None:
        key = tuple(label_values.get(lbl, "") for lbl in self.labels)
        with self._lock:
            self._values[key] = value

    def get(self, **label_values: str) -> float:
        key = tuple(label_values.get(lbl, "") for lbl in self.labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} gauge",
        ]
        with self._lock:
            items = list(self._values.items())
        for key, value in items:
            label_str = _fmt_labels(self.labels, key)
            lines.append(f"{self.name}{label_str} {value}")
        if not items:
            lines.append(f"{self.name} 0")
        return "\n".join(lines)

    def reset(self) -> None:
        with self._lock:
            self._values.clear()


class Histogram:
    """Thread-safe histogram with fixed buckets for latency tracking."""

    _BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(self, name: str, help_text: str, labels: tuple[str, ...] = ()) -> None:
        self.name = name
        self.help_text = help_text
        self.labels = labels
        self._counts: dict[tuple, list[int]] = defaultdict(lambda: [0] * len(self._BUCKETS))
        self._sums: dict[tuple, float] = defaultdict(float)
        self._totals: dict[tuple, int] = defaultdict(int)
        self._lock = threading.Lock()

    def observe(self, value: float, **label_values: str) -> None:
        key = tuple(label_values.get(lbl, "") for lbl in self.labels)
        with self._lock:
            for i, bound in enumerate(self._BUCKETS):
                if value <= bound:
                    self._counts[key][i] += 1
            self._sums[key] += value
            self._totals[key] += 1

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} histogram",
        ]
        with self._lock:
            keys = list(self._totals.keys())
        for key in keys:
            label_str = _fmt_labels(self.labels, key)
            cumulative = 0
            with self._lock:
                counts = list(self._counts[key])
                total_sum = self._sums[key]
                total_count = self._totals[key]
            for i, bound in enumerate(self._BUCKETS):
                cumulative += counts[i]
                le_str = f'+Inf' if bound >= 1e9 else str(bound)
                lb = label_str.rstrip("}") + f', le="{bound}"' + "}" if label_str else f'{{le="{bound}"}}'
                lines.append(f"{self.name}_bucket{lb} {cumulative}")
            inf_lb = label_str.rstrip("}") + ', le="+Inf"}' if label_str else '{le="+Inf"}'
            lines.append(f"{self.name}_bucket{inf_lb} {total_count}")
            lines.append(f"{self.name}_sum{label_str} {total_sum}")
            lines.append(f"{self.name}_count{label_str} {total_count}")
        return "\n".join(lines)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
            self._sums.clear()
            self._totals.clear()


# ── Metrics collector ──────────────────────────────────────────────────────────


class MetricsCollector:
    """Central registry for all squash runtime metrics."""

    def __init__(self) -> None:
        self.attestations_total = Counter(
            "squash_attestations_total",
            "Total number of squash attestation runs.",
            labels=("result", "policy"),
        )
        self.policy_violations_total = Counter(
            "squash_policy_violations_total",
            "Total number of policy violations detected.",
            labels=("policy",),
        )
        self.drift_events_total = Counter(
            "squash_drift_events_total",
            "Total number of model drift events detected.",
            labels=("model_id",),
        )
        self.models_compliant_ratio = Gauge(
            "squash_models_compliant_ratio",
            "Ratio of compliant attestations to total attestations (0.0–1.0).",
        )
        self.quota_used_total = Counter(
            "squash_quota_used_total",
            "Total attestation quota consumed across all API keys.",
            labels=("plan",),
        )
        self.api_requests_total = Counter(
            "squash_api_requests_total",
            "Total number of HTTP requests processed by the squash API.",
            labels=("method", "endpoint", "status_code"),
        )
        self.api_latency_seconds = Histogram(
            "squash_api_latency_seconds",
            "HTTP response latency in seconds.",
            labels=("method", "endpoint"),
        )

        self._total_attestations = 0
        self._passed_attestations = 0
        self._lock = threading.Lock()

    # ── High-level helpers ────────────────────────────────────────────────────

    def inc_attestation(self, passed: bool, policy: str = "") -> None:
        result = "passed" if passed else "failed"
        self.attestations_total.inc(result=result, policy=policy)
        with self._lock:
            self._total_attestations += 1
            if passed:
                self._passed_attestations += 1
            ratio = (self._passed_attestations / self._total_attestations
                     if self._total_attestations > 0 else 1.0)
        self.models_compliant_ratio.set(ratio)

    def inc_violation(self, policy: str = "") -> None:
        self.policy_violations_total.inc(policy=policy)

    def inc_drift(self, model_id: str = "") -> None:
        self.drift_events_total.inc(model_id=model_id)

    def inc_quota(self, plan: str = "") -> None:
        self.quota_used_total.inc(plan=plan)

    def record_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        latency_seconds: float,
    ) -> None:
        self.api_requests_total.inc(
            method=method,
            endpoint=endpoint,
            status_code=str(status_code),
        )
        self.api_latency_seconds.observe(latency_seconds, method=method, endpoint=endpoint)

    # ── Rendering ─────────────────────────────────────────────────────────────

    def render(self) -> str:
        """Return Prometheus text exposition format (version 0.0.4)."""
        sections = [
            self.attestations_total.render(),
            self.policy_violations_total.render(),
            self.drift_events_total.render(),
            self.models_compliant_ratio.render(),
            self.quota_used_total.render(),
            self.api_requests_total.render(),
            self.api_latency_seconds.render(),
        ]
        return "\n".join(sections) + "\n"

    def reset(self) -> None:
        """Reset all metrics (for test isolation)."""
        for attr in vars(self).values():
            if isinstance(attr, (Counter, Gauge, Histogram)):
                attr.reset()
        with self._lock:
            self._total_attestations = 0
            self._passed_attestations = 0


# ── Module-level singleton ─────────────────────────────────────────────────────

_collector: MetricsCollector | None = None


def get_collector() -> MetricsCollector:
    """Return the module-level metrics singleton."""
    global _collector
    if _collector is None:
        _collector = MetricsCollector()
    return _collector


def reset_collector() -> MetricsCollector:
    """Reset the singleton (for test isolation)."""
    global _collector
    _collector = MetricsCollector()
    return _collector


# ── Internal helpers ───────────────────────────────────────────────────────────


def _fmt_labels(label_names: tuple[str, ...], values: tuple) -> str:
    if not label_names or not values:
        return ""
    parts = [f'{k}="{v}"' for k, v in zip(label_names, values)]
    return "{" + ", ".join(parts) + "}"
