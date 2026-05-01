"""tests/test_hallucination_monitor.py — W267-W269 / C10 Runtime Hallucination Monitor.

Test taxonomy:

PART 1 — score_live_response (three modes)
  * Grounded: faithful response not hallucinated
  * Grounded: unrelated response hallucinated
  * RAG context-only: grounded response scores high
  * RAG context-only: unsupported entity flagged
  * Black-box heuristic: absolute claims lower score
  * Black-box: hedging language raises score
  * Empty response hallucinated in all modes

PART 2 — RollingWindow
  * Append and retrieve entries
  * Rate computation: all faithful → 0%
  * Rate computation: all hallucinated → 100%
  * Mixed rate correct
  * Since filter: only recent entries counted
  * Persistence across instances (JSONL reload)
  * maxsize eviction
  * Clear works

PART 3 — RequestSampler
  * sample_rate=1.0 scores every request
  * sample_rate=0.0-ish rarely scores (statistical)
  * force_score always scores
  * scored entries appear in window
  * request_hash is a hash (not raw prompt)
  * response_preview capped at 200 chars

PART 4 — BreachEngine
  * Below threshold → no breach
  * Above threshold with insufficient samples → no breach
  * Above threshold CI lo below threshold → no breach (statistical noise)
  * Confirmed breach fires
  * on_breach callback invoked
  * score_batch: all faithful → no breach
  * score_batch: all hallucinated → breach

PART 5 — build_monitor_report
  * Status OK / WARN / BREACH
  * Schema correct

PART 6 — CLI smoke
  * Parser registered
  * score subcommand JSON output
  * batch subcommand with faithful data
  * status on empty window
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from squash.hallucination_monitor import (
    BreachEngine,
    InferenceRequest,
    RequestSampler,
    RollingWindow,
    WindowEntry,
    BreachEvent,
    build_monitor_report,
    score_batch,
    score_live_response,
    _MIN_SAMPLES_FOR_BREACH,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(hallucinated: bool, offset_secs: int = 0) -> WindowEntry:
    ts = (datetime.now(tz=timezone.utc) - timedelta(seconds=offset_secs)).isoformat()
    return WindowEntry(
        entry_id=f"e-{offset_secs}",
        timestamp=ts,
        request_hash="abc123",
        response_preview="resp",
        context_preview="ctx",
        faithfulness_score=0.1 if hallucinated else 0.9,
        hallucinated=hallucinated,
    )


def _req(
    response: str,
    context: str = "",
    ground_truth: str = "",
    prompt: str = "test",
) -> InferenceRequest:
    return InferenceRequest(
        prompt=prompt,
        response=response,
        context=context,
        ground_truth=ground_truth,
    )


# ---------------------------------------------------------------------------
# Part 1 — score_live_response
# ---------------------------------------------------------------------------

def test_grounded_faithful_not_hallucinated():
    s, h, bd = score_live_response(
        "Paris is the capital of France.",
        context="Paris is the capital of France.",
        ground_truth="Paris is the capital of France.",
    )
    assert not h
    assert s > 0.4
    assert bd["mode"] == "grounded"


def test_grounded_unrelated_hallucinated():
    s, h, bd = score_live_response(
        "The Eiffel Tower is in Paris.",
        context="The moon orbits Earth.",
        ground_truth="Water boils at 100°C.",
    )
    assert h


def test_rag_context_grounded_not_hallucinated():
    ctx = "Paris is the capital of France and has 2.1 million residents."
    s, h, bd = score_live_response(
        "Paris is the capital of France.",
        context=ctx,
    )
    assert bd["mode"] == "rag_context_only"
    assert not h   # response is in context


def test_rag_context_unsupported_entity_flagged():
    ctx = "Paris is the capital of France."
    # Response introduces Tokyo which is NOT in context
    s, h, bd = score_live_response(
        "Tokyo is a major city with 14 million people.",
        context=ctx,
    )
    assert bd["mode"] == "rag_context_only"
    # Should flag unsupported entities (Tokyo not in context)
    assert bd.get("unsupported_entities") or h


def test_blackbox_absolute_claim_lowers_score():
    s1, _, bd1 = score_live_response("The answer is probably around 42.")
    s2, _, bd2 = score_live_response("Definitely 100% guaranteed to be exactly 42,000.")
    assert bd1["mode"] == "heuristic"
    assert s1 >= s2   # more hedging = better score


def test_blackbox_hedging_raises_score():
    s1, _, _ = score_live_response("I think the answer might be approximately 42.")
    s2, _, _ = score_live_response("Definitely the answer is 42.")
    assert s1 >= s2


def test_empty_response_hallucinated_grounded():
    s, h, _ = score_live_response(
        "",
        context="Paris is the capital.",
        ground_truth="Paris.",
    )
    assert h


def test_empty_response_hallucinated_blackbox():
    s, h, _ = score_live_response("")
    assert h


# ---------------------------------------------------------------------------
# Part 2 — RollingWindow
# ---------------------------------------------------------------------------

def test_window_append_and_retrieve(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    w.append(_entry(False))
    w.append(_entry(True))
    assert len(w.entries()) == 2


def test_window_all_faithful_zero_rate(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    for _ in range(5):
        w.append(_entry(False))
    rate, lo, hi, n = w.rate()
    assert rate == 0.0
    assert n == 5
    assert lo == 0.0


def test_window_all_hallucinated_full_rate(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    for _ in range(10):
        w.append(_entry(True))
    rate, lo, hi, n = w.rate()
    assert rate == 1.0
    assert n == 10


def test_window_mixed_rate_correct(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    for _ in range(8):
        w.append(_entry(False))
    for _ in range(2):
        w.append(_entry(True))
    rate, _, _, n = w.rate()
    assert abs(rate - 0.2) < 0.01
    assert n == 10


def test_window_since_filter(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    # 5 old entries (61 min ago)
    for i in range(5):
        w.append(_entry(True, offset_secs=61 * 60))
    # 3 recent entries
    for _ in range(3):
        w.append(_entry(False))
    since = datetime.now(tz=timezone.utc) - timedelta(minutes=60)
    recent = w.entries(since=since)
    assert len(recent) == 3


def test_window_persists_across_instances(tmp_path):
    w1 = RollingWindow(state_dir=tmp_path)
    w1.append(_entry(True))
    w1.append(_entry(False))
    # New instance reads the JSONL
    w2 = RollingWindow(state_dir=tmp_path)
    assert len(w2.entries()) == 2


def test_window_maxsize_eviction(tmp_path):
    w = RollingWindow(max_entries=5, state_dir=tmp_path)
    for i in range(10):
        w.append(_entry(False))
    assert len(w.entries()) == 5


def test_window_clear(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    for _ in range(5):
        w.append(_entry(True))
    w.clear()
    assert w.entries() == []


# ---------------------------------------------------------------------------
# Part 3 — RequestSampler
# ---------------------------------------------------------------------------

def test_sampler_rate_1_scores_every_request(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    s = RequestSampler(sample_rate=1.0, window=w)
    for _ in range(10):
        result = s.maybe_score(_req("Paris is the capital."))
        assert result is not None
    assert len(w.entries()) == 10


def test_sampler_force_score_always_scores(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    s = RequestSampler(sample_rate=0.0001, window=w)  # effectively never samples
    entry = s.force_score(_req("Response text."))
    assert entry is not None
    assert len(w.entries()) == 1


def test_sampler_request_hash_not_raw_prompt(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    s = RequestSampler(sample_rate=1.0, window=w)
    entry = s.force_score(_req("My secret prompt content."))
    assert "My secret prompt" not in entry.request_hash
    assert len(entry.request_hash) == 16  # SHA-256[:16] hex


def test_sampler_response_preview_capped(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    s = RequestSampler(sample_rate=1.0, window=w)
    long_response = "x" * 500
    entry = s.force_score(_req(long_response))
    assert len(entry.response_preview) <= 200


def test_sampler_invalid_sample_rate():
    with pytest.raises(ValueError):
        RequestSampler(sample_rate=0.0)
    with pytest.raises(ValueError):
        RequestSampler(sample_rate=1.5)


def test_sampler_thread_safe(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    s = RequestSampler(sample_rate=1.0, window=w, seed=42)
    errors = []

    def worker():
        for _ in range(20):
            try:
                s.force_score(_req("response"))
            except Exception as e:
                errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(w.entries()) == 100


# ---------------------------------------------------------------------------
# Part 4 — BreachEngine
# ---------------------------------------------------------------------------

def _make_window_with_rate(rate: float, n: int, tmp_path: Path) -> RollingWindow:
    w = RollingWindow(state_dir=tmp_path)
    h_count = round(rate * n)
    for i in range(n):
        w.append(_entry(i < h_count))
    return w


def test_breach_below_threshold_no_breach(tmp_path):
    w = _make_window_with_rate(0.05, 50, tmp_path)
    engine = BreachEngine(threshold=0.10)
    assert engine.check(w) is None


def test_breach_insufficient_samples_no_breach(tmp_path):
    w = _make_window_with_rate(1.0, _MIN_SAMPLES_FOR_BREACH - 1, tmp_path)
    engine = BreachEngine(threshold=0.10)
    assert engine.check(w) is None


def test_breach_ci_lo_below_threshold_no_breach(tmp_path):
    # 1 hallucination out of 10 = 10% rate but CI lo < 10% (statistical noise)
    w = RollingWindow(state_dir=tmp_path)
    w.append(_entry(True))
    for _ in range(9):
        w.append(_entry(False))
    engine = BreachEngine(threshold=0.10)
    result = engine.check(w)
    # With n=10 and 1 hallucination, CI lo ≈ 1.8% < threshold 10% → no breach
    assert result is None


def test_breach_confirmed_fires(tmp_path):
    # 30 hallucinations out of 50 = 60%, CI lo >> 10%
    w = _make_window_with_rate(0.60, 50, tmp_path)
    engine = BreachEngine(threshold=0.10)
    event = engine.check(w)
    assert event is not None
    assert event.observed_rate > 0.10
    assert event.ci_low > 0.10
    assert event.schema == "squash.hallucination.monitor.breach/v1"


def test_breach_callback_invoked(tmp_path):
    w = _make_window_with_rate(0.60, 50, tmp_path)
    called = []
    engine = BreachEngine(threshold=0.10, on_breach=lambda ev: called.append(ev))
    engine.check(w)
    assert len(called) == 1
    assert called[0].observed_rate > 0.10


def test_score_batch_faithful_no_breach(tmp_path):
    reqs = [_req("Paris is the capital of France.",
                 context="Paris is the capital of France.",
                 ground_truth="Paris is the capital of France.") for _ in range(15)]
    w = RollingWindow(state_dir=tmp_path)
    result = score_batch(reqs, threshold=0.50, window=w)
    assert result["passes_threshold"]
    assert result["breach"] is None


def test_score_batch_all_hallucinated_breach(tmp_path):
    # Negation conflict reliably triggers hallucination
    reqs = [_req("ACE inhibitors are NOT contraindicated in pregnancy.",
                 context="ACE inhibitors are contraindicated in pregnancy.",
                 ground_truth="ACE inhibitors are contraindicated in pregnancy.") for _ in range(20)]
    w = RollingWindow(state_dir=tmp_path)
    result = score_batch(reqs, threshold=0.10, window=w)
    assert not result["passes_threshold"]
    assert result["breach"] is not None


def test_score_batch_schema(tmp_path):
    reqs = [_req("answer") for _ in range(5)]
    result = score_batch(reqs)
    assert result["schema"] == "squash.hallucination.monitor.batch/v1"
    assert "hallucination_rate" in result
    assert "ci_low" in result
    assert "ci_high" in result


# ---------------------------------------------------------------------------
# Part 5 — build_monitor_report
# ---------------------------------------------------------------------------

def test_monitor_report_status_ok(tmp_path):
    w = _make_window_with_rate(0.02, 30, tmp_path)
    r = build_monitor_report(w, threshold=0.10, window_minutes=60)
    assert r["status"] == "OK"
    assert r["schema"] == "squash.hallucination.monitor.report/v1"


def test_monitor_report_status_warn(tmp_path):
    w = _make_window_with_rate(0.09, 30, tmp_path)  # 90% of threshold → WARN
    r = build_monitor_report(w, threshold=0.10, window_minutes=60)
    assert r["status"] in ("WARN", "BREACH")


def test_monitor_report_status_breach(tmp_path):
    w = _make_window_with_rate(0.50, 30, tmp_path)
    r = build_monitor_report(w, threshold=0.10, window_minutes=60)
    assert r["status"] == "BREACH"


def test_monitor_report_empty_window(tmp_path):
    w = RollingWindow(state_dir=tmp_path)
    r = build_monitor_report(w, threshold=0.10)
    assert r["sample_count"] == 0
    assert r["hallucination_rate"] == 0.0
    assert r["status"] == "OK"


# ---------------------------------------------------------------------------
# Part 6 — CLI smoke
# ---------------------------------------------------------------------------

def test_cli_parser_registered():
    from squash.cli import _build_parser
    p = _build_parser()
    ns = p.parse_args(["hallucination-monitor", "run",
                       "--endpoint", "mock://test", "--once"])
    assert ns.command == "hallucination-monitor"
    assert ns.hm_command == "run"
    assert ns.once is True


def test_cli_score_json_output(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_hallucination_monitor
    args = argparse.Namespace(
        hm_command="score",
        response="Paris is the capital of France.",
        context="Paris is the capital of France.",
        ground_truth="Paris is the capital of France.",
        output_json=True,
    )
    rc = _cmd_hallucination_monitor(args, quiet=True)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "score" in payload
    assert "hallucinated" in payload
    assert payload["hallucinated"] is False
    assert rc == 0


def test_cli_score_hallucinated_exits_2(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_hallucination_monitor
    args = argparse.Namespace(
        hm_command="score",
        response="",    # empty → hallucinated
        context="Paris is the capital.",
        ground_truth="Paris.",
        output_json=True,
    )
    rc = _cmd_hallucination_monitor(args, quiet=True)
    assert rc == 2


def test_cli_status_empty_window(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_hallucination_monitor
    args = argparse.Namespace(
        hm_command="status",
        state_dir=str(tmp_path),
        threshold=0.10,
        window_minutes=60,
        output_json=True,
    )
    rc = _cmd_hallucination_monitor(args, quiet=True)
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["sample_count"] == 0
    assert payload["status"] == "OK"


def test_cli_batch_faithful(tmp_path, capsys):
    import argparse
    from squash.cli import _cmd_hallucination_monitor
    data = [
        {"prompt": "q", "response": "Paris.",
         "context": "Paris is the capital.", "ground_truth": "Paris."}
        for _ in range(5)
    ]
    req_file = tmp_path / "reqs.json"
    req_file.write_text(json.dumps(data))
    args = argparse.Namespace(
        hm_command="batch",
        requests_file=str(req_file),
        model_id="test",
        threshold=0.50,
        fail_on_breach=False,
        output_json=True,
    )
    rc = _cmd_hallucination_monitor(args, quiet=True)
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passes_threshold"]


def test_cli_run_once_mode(tmp_path, capsys):
    """--once mode should return immediately after one poll."""
    import argparse
    from squash.cli import _cmd_hallucination_monitor
    args = argparse.Namespace(
        hm_command="run",
        endpoint="mock://test",
        model_id="test",
        sample_rate=1.0,
        threshold=1.0,    # never breach
        window_minutes=60,
        poll_interval=30.0,
        once=True,
        state_dir=str(tmp_path),
        hm_format="json",
    )
    rc = _cmd_hallucination_monitor(args, quiet=True)
    assert rc == 0
    # Window should have one entry now
    w = RollingWindow(state_dir=tmp_path)
    assert len(w.entries()) >= 1
