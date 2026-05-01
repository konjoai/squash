"""squash/hallucination_monitor.py — Runtime Hallucination Monitor (C10 / W267-W269).

Why pre-deploy attestation is not enough
-----------------------------------------
C7 (`squash hallucination-attest`) attests a model before launch: you run a
fixed probe set, get a signed rate, and deploy. This is the **static** picture.

EU AI Act Article 9 requires something harder: **post-market monitoring**
throughout the AI system's deployment lifecycle. The regulation distinguishes
between:

* Initial conformity assessment (C7, Annex IV): done before first deploy
* Ongoing monitoring (Article 9(1)(f)): continuous obligation

The statistics confirm why this matters:
* **18%** production hallucination rate in enterprise chatbot deployments
* **5–15%** in RAG systems even with retrieval working correctly
* **39%** of enterprise AI customer-service bots pulled or reworked in 2024
  due to hallucination errors

Models degrade. Prompts drift. Data pipelines shift. A model that scored
1.2% on the legal probe set at deploy time may be running at 8.4% six
months later because the system prompt changed, the retrieval corpus aged,
or the model was quietly updated by the provider.

C10 is the monitor that catches this before regulators do.

Architecture
-------------
The monitor operates in three layers:

**Layer 1 — Sampler** (``RequestSampler``)
    Intercepts inference requests and responses at configurable sample rate
    (default 5%). For each sampled pair, scores the response for faithfulness
    using C7's scorer. Writes to the rolling window. Zero overhead on
    un-sampled requests.

**Layer 2 — Rolling Window** (``RollingWindow``)
    Append-only fixed-size ring buffer of ``WindowEntry`` records. Computes
    current hallucination rate and 95% Wilson CI on demand. Persisted to
    a JSONL file so the monitor survives restarts without losing history.

**Layer 3 — Breach Engine** (``BreachEngine``)
    Polls the rolling window at configurable interval. When the hallucination
    rate exceeds the threshold AND the CI lower-bound also exceeds threshold
    (confirmed breach, not statistical noise), fires a breach event via
    ``webhook_delivery.notify()`` and logs the violation to the
    ``attestation_registry``.

Deployment modes
-----------------
``squash monitor --mode hallucination --endpoint URL [--sample-rate 0.05]``

1. **Cron / batch** — pass ``--once`` to score one request and exit. Ideal
   for a Kubernetes CronJob that samples at regular intervals.
2. **Long-running** — omit ``--once`` to run continuously, polling the
   endpoint at ``--poll-interval`` seconds. Suitable for a sidecar container.
3. **Sidecar proxy** — pass requests through via ``--proxy-mode`` (future):
   the monitor acts as a reverse proxy, scoring every sampled response inline.

Distinct from C7
-----------------
* C7: signed certificate for a fixed probe set (known Q&A pairs) — evaluates
  the model in isolation.
* C10: scores live traffic against its own context (when RAG context is
  available) or detects absolute-claim / negation-pattern hallucinations
  in free-form responses. Does not require ground-truth pairs.

The two complement: C7 for pre-deploy gatekeeping, C10 for post-deploy SLA.

Konjo notes
-----------
* 건조 — reuses ``score_faithfulness`` from C7 without copying it. One scorer,
  two deployment modes. DRY at the architectural level, not just the code.
* ᨀᨚᨐᨚ — the rolling window is a simple JSONL file. Any engineer can open it,
  read every sample, and reproduce the rate from scratch. No opaque database.
* 康宙 — the sampler adds zero latency to un-sampled requests. Sample rate
  defaults to 5% so 95% of production traffic is unaffected.
* 根性 — EU AI Act Article 9(1)(f) is a hard obligation. The monitor is not
  optional infrastructure — it is the compliance artefact that regulators
  will request on day 1 of an examination.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rolling window entry
# ---------------------------------------------------------------------------

@dataclass
class WindowEntry:
    """One scored sample in the rolling window."""
    entry_id:          str
    timestamp:         str          # ISO-8601 UTC
    request_hash:      str          # SHA-256[:16] of the prompt — never stored raw
    response_preview:  str          # first 200 chars of response (for audit trail)
    context_preview:   str          # first 200 chars of context if available
    faithfulness_score:float
    hallucinated:      bool
    score_breakdown:   dict[str, Any] = field(default_factory=dict)
    model_id:          str = ""
    endpoint:          str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Rolling window
# ---------------------------------------------------------------------------

class RollingWindow:
    """Fixed-size append-only ring buffer of faithfulness samples.

    Persists to ``<state_dir>/rolling_window.jsonl`` so the monitor survives
    restarts. The file never grows beyond ``max_entries`` lines — old entries
    are evicted as new ones arrive.
    """

    def __init__(
        self,
        max_entries: int = 1000,
        state_dir: Path | None = None,
    ) -> None:
        self.max_entries = max_entries
        self.state_dir = Path(state_dir) if state_dir else (
            Path.home() / ".squash" / "monitor"
        )
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._path = self.state_dir / "rolling_window.jsonl"
        self._entries: deque[WindowEntry] = deque(maxlen=max_entries)
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        for line in self._path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                self._entries.append(WindowEntry(**d))
            except Exception:
                pass

    def _flush(self) -> None:
        self._path.write_text(
            "\n".join(json.dumps(e.to_dict(), sort_keys=True)
                      for e in self._entries) + "\n"
        )

    def append(self, entry: WindowEntry) -> None:
        with self._lock:
            self._entries.append(entry)
            self._flush()

    def entries(self, since: datetime | None = None) -> list[WindowEntry]:
        with self._lock:
            all_e = list(self._entries)
        if since is None:
            return all_e
        return [e for e in all_e
                if _parse_iso(e.timestamp) >= since]

    def rate(self, since: datetime | None = None) -> tuple[float, float, float, int]:
        """Return (rate, ci_lo, ci_hi, n) for the window."""
        es = self.entries(since)
        n = len(es)
        if n == 0:
            return 0.0, 0.0, 1.0, 0
        h = sum(1 for e in es if e.hallucinated)
        from squash.hallucination_attest import _wilson_ci
        lo, hi = _wilson_ci(h, n)
        return h / n, lo, hi, n

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._path.write_text("")


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


# ---------------------------------------------------------------------------
# Faithfulness scorer for live traffic
# ---------------------------------------------------------------------------

def score_live_response(
    response: str,
    context: str = "",
    ground_truth: str = "",
    prompt: str = "",
) -> tuple[float, bool, dict[str, Any]]:
    """Score a live response for hallucination risk.

    When ``context`` is provided (RAG mode): use the full C7 scorer with
    context as the grounding reference.

    When only ``response`` is available (black-box mode): apply structural
    heuristics — absolute claim detection, negation-dominant patterns,
    unsupported named-entity density — without requiring a reference.

    Returns ``(faithfulness_score, hallucinated, breakdown)``.
    """
    from squash.hallucination_attest import score_faithfulness, _extract_entities, _tokenize

    if context and ground_truth:
        # Full grounded mode
        fs = score_faithfulness(ground_truth, response, context)
        return fs.composite, fs.hallucinated, {
            "mode": "grounded",
            "token_f1": fs.token_f1,
            "ngram_cosine": fs.ngram_cosine,
            "negation_conflict": fs.negation_conflict,
            "unsupported_entities": fs.unsupported_entities,
        }

    if context:
        # Context-only RAG mode: response should be grounded in context
        from squash.hallucination_attest import _token_f1, _char_ngrams, _cosine, _has_negation
        tf1 = _token_f1(response, context)
        ng  = _cosine(_char_ngrams(response), _char_ngrams(context))
        # In RAG mode a response grounded in the context has high overlap
        composite = 0.6 * tf1 + 0.4 * ng
        resp_entities = _extract_entities(response)
        ctx_entities  = _extract_entities(context)
        unsupported = bool(resp_entities - ctx_entities) and tf1 < 0.15
        hallucinated = composite < 0.10 or unsupported
        return composite, hallucinated, {
            "mode": "rag_context_only",
            "token_f1": round(tf1, 4),
            "ngram_cosine": round(ng, 4),
            "unsupported_entities": unsupported,
        }

    # Black-box structural heuristics
    if not response.strip():
        return 0.0, True, {"mode": "heuristic", "flags": ["empty_response"], "score": 0.0}
    score, breakdown = _heuristic_score(response)
    return score, score < 0.3, breakdown


# Absolute claim indicators — strongly correlated with hallucination in
# production deployments (Slobodkin et al. 2023; Xiong et al. 2024)
_ABSOLUTE_PATTERNS = [
    r"\b(?:definitely|certainly|absolutely|always|never|guaranteed|100%|perfect)\b",
    r"\b(?:as of \d{4}|according to|studies? show|research shows|experts? say)\b",
    r"\b(?:the (?:latest|most recent|current|newest|best|only))\b",
    r"\b(?:invented|discovered|created|founded|born|died)\s+in\s+\d{4}\b",
    r"\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\b",  # large specific numbers in free-form
]
_ABSOLUTE_RE = [__import__("re").compile(p, __import__("re").I) for p in _ABSOLUTE_PATTERNS]


def _heuristic_score(response: str) -> tuple[float, dict[str, Any]]:
    """Structural risk score for a response with no reference."""
    import re
    score = 0.8   # start optimistic
    flags: list[str] = []

    for pat in _ABSOLUTE_RE:
        m = pat.search(response)
        if m:
            flags.append(f"absolute_claim: {m.group(0)[:40]!r}")
            score -= 0.08

    # Long, specific, number-dense responses have higher hallucination risk
    words = response.split()
    if len(words) > 200:
        score -= 0.05
        flags.append("long_response")

    # Hedging language is negatively correlated with hallucination
    hedges = len(__import__("re").findall(
        r"\b(?:might|may|could|possibly|likely|I think|I believe|unclear|not sure)\b",
        response, __import__("re").I
    ))
    if hedges > 0:
        score += min(0.10, hedges * 0.03)
        flags.append(f"hedging_language:{hedges}")

    score = max(0.0, min(1.0, score))
    return score, {"mode": "heuristic", "flags": flags, "score": round(score, 4)}


# ---------------------------------------------------------------------------
# Request sampler
# ---------------------------------------------------------------------------

@dataclass
class InferenceRequest:
    """One live inference request + response pair to score."""
    prompt:    str
    response:  str
    context:   str = ""            # RAG context, if available
    ground_truth: str = ""         # known answer, if available
    model_id:  str = ""
    endpoint:  str = ""
    metadata:  dict[str, Any] = field(default_factory=dict)


class RequestSampler:
    """Sample live inference traffic and score each selected pair.

    Thread-safe. Designed to be called from a request-processing loop or
    middleware. Scoring runs synchronously in the caller's thread — if this
    is unacceptable for latency-sensitive paths, wrap the ``maybe_score``
    call in a background thread pool.
    """

    def __init__(
        self,
        sample_rate: float = 0.05,
        window: RollingWindow | None = None,
        seed: int | None = None,
    ) -> None:
        if not 0.0 < sample_rate <= 1.0:
            raise ValueError(f"sample_rate must be in (0, 1]; got {sample_rate}")
        self.sample_rate = sample_rate
        self.window = window or RollingWindow()
        self._rng = random.Random(seed)
        self._lock = threading.Lock()

    def maybe_score(self, req: InferenceRequest) -> WindowEntry | None:
        """Score ``req`` with probability ``sample_rate``. Returns None if not sampled."""
        with self._lock:
            if self._rng.random() > self.sample_rate:
                return None
        return self._score(req)

    def force_score(self, req: InferenceRequest) -> WindowEntry:
        """Score unconditionally — useful for explicit monitoring calls."""
        return self._score(req)

    def _score(self, req: InferenceRequest) -> WindowEntry:
        fs, hallucinated, breakdown = score_live_response(
            response=req.response,
            context=req.context,
            ground_truth=req.ground_truth,
            prompt=req.prompt,
        )
        req_hash = hashlib.sha256(req.prompt.encode()).hexdigest()[:16]
        entry = WindowEntry(
            entry_id="mon-" + uuid.uuid4().hex[:12],
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            request_hash=req_hash,
            response_preview=req.response[:200],
            context_preview=req.context[:200],
            faithfulness_score=round(fs, 4),
            hallucinated=hallucinated,
            score_breakdown=breakdown,
            model_id=req.model_id,
            endpoint=req.endpoint,
        )
        self.window.append(entry)
        return entry


# ---------------------------------------------------------------------------
# Breach detection
# ---------------------------------------------------------------------------

_SCHEMA = "squash.hallucination.monitor.breach/v1"
_MIN_SAMPLES_FOR_BREACH = 10    # don't fire breach on statistical noise


@dataclass
class BreachEvent:
    """Fired when hallucination rate exceeds threshold with statistical confidence."""
    breach_id:          str
    schema:             str
    model_id:           str
    endpoint:           str
    threshold:          float
    observed_rate:      float
    ci_low:             float
    ci_high:            float
    sample_count:       int
    window_minutes:     int
    timestamp:          str
    violations:         list[dict[str, Any]]  # recent hallucinated entries
    squash_version:     str = "1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def summary(self) -> str:
        return (
            f"[BREACH] hallucination rate {self.observed_rate:.1%} "
            f"(CI [{self.ci_low:.1%}, {self.ci_high:.1%}]) "
            f"exceeds threshold {self.threshold:.1%} "
            f"— {self.sample_count} samples in {self.window_minutes}min window"
        )


class BreachEngine:
    """Poll the rolling window and fire breach events when threshold is exceeded.

    A breach is confirmed only when BOTH conditions hold:
    1. The point estimate exceeds the threshold.
    2. The 95% CI lower bound ALSO exceeds the threshold.

    This prevents false alarms from small samples where the rate randomly
    spikes. At 10 samples, a 20% rate has CI [5.7%, 51.3%] — if the
    threshold is 10% the CI lo is below threshold, so no breach fires.
    At 100 samples with 20% rate the CI is [13.5%, 28.7%] — breach fires.
    """

    def __init__(
        self,
        threshold: float = 0.10,
        window_minutes: int = 60,
        model_id: str = "",
        endpoint: str = "",
        on_breach: Any = None,
    ) -> None:
        self.threshold = threshold
        self.window_minutes = window_minutes
        self.model_id = model_id
        self.endpoint = endpoint
        self.on_breach = on_breach  # callable(BreachEvent) | None
        self._last_breach_id: str | None = None

    def check(self, window: RollingWindow) -> BreachEvent | None:
        """Check the window and return a BreachEvent if breach is confirmed."""
        since = datetime.now(tz=timezone.utc) - timedelta(minutes=self.window_minutes)
        rate, ci_lo, ci_hi, n = window.rate(since=since)

        if n < _MIN_SAMPLES_FOR_BREACH:
            return None
        if rate <= self.threshold:
            return None
        if ci_lo <= self.threshold:
            # Statistical noise — CI lo is below threshold, not confirmed
            return None

        # Confirmed breach
        entries = window.entries(since=since)
        violations = [
            e.to_dict() for e in entries
            if e.hallucinated
        ][:20]  # cap violation list to 20

        event = BreachEvent(
            breach_id="brc-" + uuid.uuid4().hex[:12],
            schema=_SCHEMA,
            model_id=self.model_id,
            endpoint=self.endpoint,
            threshold=self.threshold,
            observed_rate=round(rate, 6),
            ci_low=round(ci_lo, 6),
            ci_high=round(ci_hi, 6),
            sample_count=n,
            window_minutes=self.window_minutes,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            violations=violations,
        )
        self._last_breach_id = event.breach_id

        if self.on_breach:
            try:
                self.on_breach(event)
            except Exception as exc:
                log.warning("on_breach callback failed: %s", exc)

        return event


# ---------------------------------------------------------------------------
# Webhook + registry integration
# ---------------------------------------------------------------------------

def notify_breach(event: BreachEvent, db_path: Path | None = None) -> None:
    """Fire webhook notification and log to attestation registry.

    Uses existing ``webhook_delivery`` and ``attestation_registry``
    infrastructure — C10 produces no new storage format.
    """
    payload = event.to_dict()

    # Webhook delivery (best-effort)
    try:
        from squash.webhook_delivery import WebhookDelivery
        wd = WebhookDelivery(db_path=db_path)
        wd.notify(event_type="hallucination.threshold_breach", payload=payload)
    except Exception as exc:
        log.warning("webhook delivery failed: %s", exc)

    # Attestation registry log (best-effort)
    try:
        from squash.attestation_registry import AttestationRegistry
        registry = AttestationRegistry(db_path=db_path)
        registry.publish(
            org="squash-monitor",
            model_id=event.model_id or "unknown",
            model_version="runtime",
            payload=json.dumps(payload).encode(),
            frameworks=["hallucination-monitor"],
            compliance_score=max(0.0, (1.0 - event.observed_rate) * 100),
            is_public=False,
        )
        registry.close()
    except Exception as exc:
        log.warning("attestation registry log failed: %s", exc)


# ---------------------------------------------------------------------------
# Batch scorer — for offline / cron use
# ---------------------------------------------------------------------------

def score_batch(
    requests: list[InferenceRequest],
    threshold: float = 0.10,
    model_id: str = "",
    endpoint: str = "",
    window: RollingWindow | None = None,
) -> dict[str, Any]:
    """Score a batch of inference pairs and return a summary dict.

    Suitable for cron-based monitoring where you collect N request/response
    pairs offline and then run the monitor in one pass.
    """
    w = window or RollingWindow(max_entries=len(requests) + 100)
    sampler = RequestSampler(sample_rate=1.0, window=w)  # score all
    for req in requests:
        req.model_id = req.model_id or model_id
        req.endpoint = req.endpoint or endpoint
        sampler.force_score(req)

    rate, ci_lo, ci_hi, n = w.rate()
    breach = BreachEngine(threshold=threshold, model_id=model_id, endpoint=endpoint)
    breach_event = breach.check(w)

    return {
        "schema": "squash.hallucination.monitor.batch/v1",
        "model_id": model_id,
        "endpoint": endpoint,
        "sample_count": n,
        "hallucination_rate": round(rate, 6),
        "ci_low": round(ci_lo, 6),
        "ci_high": round(ci_hi, 6),
        "threshold": threshold,
        "passes_threshold": rate <= threshold,
        "breach": breach_event.to_dict() if breach_event else None,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Daemon / poll loop
# ---------------------------------------------------------------------------

def run_monitor(
    endpoint: str,
    model_id: str = "",
    sample_rate: float = 0.05,
    threshold: float = 0.10,
    window_minutes: int = 60,
    poll_interval: float = 30.0,
    max_rate: float | None = None,
    state_dir: Path | None = None,
    on_breach: Any = None,
    stop_event: threading.Event | None = None,
    once: bool = False,
) -> None:
    """Run the hallucination monitor in daemon or single-shot mode.

    In daemon mode (``once=False``) this function blocks indefinitely,
    polling ``endpoint`` at ``poll_interval`` seconds and running breach
    detection after each sample. Use ``stop_event.set()`` to stop cleanly.

    In single-shot mode (``once=True``) this scores one request from
    the endpoint and returns, suitable for cron jobs.
    """
    effective_threshold = max_rate if max_rate is not None else threshold
    window    = RollingWindow(state_dir=state_dir)
    engine    = BreachEngine(
        threshold=effective_threshold,
        window_minutes=window_minutes,
        model_id=model_id,
        endpoint=endpoint,
        on_breach=on_breach or (lambda ev: notify_breach(ev)),
    )
    sampler   = RequestSampler(sample_rate=sample_rate, window=window)
    stop      = stop_event or threading.Event()

    log.info(
        "hallucination-monitor: endpoint=%s sample_rate=%.1f%% threshold=%.1f%% "
        "window=%dmin",
        endpoint, sample_rate * 100, effective_threshold * 100, window_minutes,
    )

    while not stop.is_set():
        try:
            _poll_once(endpoint, model_id, sampler)
            engine.check(window)
        except Exception as exc:
            log.warning("monitor poll failed: %s", exc)

        if once:
            return
        stop.wait(poll_interval)


def _poll_once(endpoint: str, model_id: str, sampler: RequestSampler) -> None:
    """Fetch one probe response from the endpoint and score it."""
    from squash.hallucination_attest import get_probes, call_model, _build_prompt
    import random as _rnd
    probes = get_probes("general")
    probe  = _rnd.choice(probes)
    prompt = _build_prompt(probe)
    try:
        response = call_model(endpoint, prompt, timeout=15)
    except Exception as exc:
        log.debug("poll_once: model call failed — %s", exc)
        return
    req = InferenceRequest(
        prompt=prompt,
        response=response,
        ground_truth=probe.ground_truth,
        context=probe.context,
        model_id=model_id,
        endpoint=endpoint,
    )
    sampler.force_score(req)


# ---------------------------------------------------------------------------
# Monitor state report
# ---------------------------------------------------------------------------

def build_monitor_report(
    window: RollingWindow,
    threshold: float = 0.10,
    window_minutes: int = 60,
    model_id: str = "",
) -> dict[str, Any]:
    """Build a human-readable monitor state report."""
    since = datetime.now(tz=timezone.utc) - timedelta(minutes=window_minutes)
    rate, ci_lo, ci_hi, n = window.rate(since=since)
    entries = window.entries(since=since)
    h_count = sum(1 for e in entries if e.hallucinated)
    return {
        "schema": "squash.hallucination.monitor.report/v1",
        "model_id": model_id,
        "window_minutes": window_minutes,
        "sample_count": n,
        "hallucinated_count": h_count,
        "hallucination_rate": round(rate, 6),
        "ci_low": round(ci_lo, 6),
        "ci_high": round(ci_hi, 6),
        "threshold": threshold,
        "status": "BREACH" if rate > threshold and n >= _MIN_SAMPLES_FOR_BREACH else (
            "WARN" if rate > threshold * 0.75 else "OK"
        ),
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
