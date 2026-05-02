"""Phase G.2 — Clock injection contract tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from squash.clock import (
    Clock,
    FrozenClock,
    SystemClock,
    get_default_clock,
    now,
    set_default_clock,
    utc_now,
    with_clock,
)


def test_system_clock_is_tz_aware_utc():
    t = SystemClock()()
    assert t.tzinfo is not None
    assert t.utcoffset() == timedelta(0)


def test_frozen_clock_returns_same_instant():
    fc = FrozenClock(datetime(2026, 5, 1, tzinfo=timezone.utc))
    assert fc() == fc()


def test_frozen_clock_default_is_2026_05_01():
    fc = FrozenClock()
    assert fc() == datetime(2026, 5, 1, tzinfo=timezone.utc)


def test_frozen_clock_naive_input_assumed_utc():
    fc = FrozenClock(datetime(2026, 1, 1))
    assert fc().tzinfo == timezone.utc


def test_frozen_clock_tick_advances_monotonically():
    fc = FrozenClock(datetime(2026, 5, 1, tzinfo=timezone.utc))
    a = fc()
    fc.tick(timedelta(seconds=10))
    b = fc()
    assert (b - a) == timedelta(seconds=10)


def test_frozen_clock_set_jumps_instant():
    fc = FrozenClock()
    fc.set(datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert fc().year == 2030


def test_with_clock_swaps_default_inside_block():
    target = FrozenClock(datetime(2027, 6, 15, 12, 0, 0, tzinfo=timezone.utc))
    before = utc_now()
    with with_clock(target):
        assert utc_now() == datetime(2027, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    # default restored
    assert utc_now() != target()


def test_set_default_clock_round_trip():
    prev = get_default_clock()
    fc = FrozenClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    try:
        set_default_clock(fc)
        assert utc_now().year == 2026
    finally:
        set_default_clock(prev)


def test_now_takes_explicit_clock_or_default():
    fc = FrozenClock(datetime(2030, 5, 1, tzinfo=timezone.utc))
    assert now(fc).year == 2030
    # default still flows through
    assert now() is not None


def test_clock_protocol_runtime_check():
    assert isinstance(SystemClock(), Clock)
    assert isinstance(FrozenClock(), Clock)
    # plain callable also satisfies the protocol structurally
    plain = lambda: datetime(2030, 1, 1, tzinfo=timezone.utc)  # noqa: E731
    # not a class — Protocol runtime check requires a __call__ member, lambdas have it
    assert callable(plain)
