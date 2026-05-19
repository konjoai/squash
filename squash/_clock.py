"""Injectable clock for reproducible attestation timestamps.

This module re-exports the public clock API from :mod:`squash.clock` so that
signing paths can import from a single canonical location.

Every attestation path that calls ``datetime.now()`` inline is non-reproducible
by construction — each call returns a different value. The fix is to accept an
injected ``clock: ClockType`` parameter (default :data:`DEFAULT_CLOCK`) so tests
can freeze time and produce byte-identical output on successive runs.

Usage::

    from squash._clock import utc_now, ClockType, DEFAULT_CLOCK, freeze_clock
    from datetime import datetime, timezone

    # Production code — uses the system clock:
    ts = utc_now()

    # Test code — freeze time:
    fixed = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    with freeze_clock(fixed):
        ts = utc_now()   # always returns fixed

    # Passing a clock explicitly:
    def make_cert(clock: ClockType = DEFAULT_CLOCK) -> dict:
        return {"issued_at": clock().isoformat()}
"""

from __future__ import annotations

import contextlib
import datetime as _dt
from typing import Callable, Iterator

from squash.clock import (
    FrozenClock as FrozenClock,          # noqa: F401 — re-export
    SystemClock as SystemClock,          # noqa: F401 — re-export
    get_default_clock as get_default_clock,  # noqa: F401 — re-export
    set_default_clock as set_default_clock,  # noqa: F401 — re-export
    with_clock as with_clock,            # noqa: F401 — re-export
    utc_now as utc_now,                  # noqa: F401 — re-export
)

__all__ = [
    "ClockType",
    "DEFAULT_CLOCK",
    "utc_now",
    "freeze_clock",
    "FrozenClock",
    "SystemClock",
]

#: Type alias for any zero-argument callable that returns a tz-aware datetime.
ClockType = Callable[[], _dt.datetime]

#: The production default clock — wraps ``datetime.now(timezone.utc)``.
DEFAULT_CLOCK: ClockType = SystemClock()


@contextlib.contextmanager
def freeze_clock(dt: _dt.datetime) -> Iterator[FrozenClock]:
    """Context manager: monkeypatch the module-level default clock to return *dt*.

    Restores the previous clock on exit even if an exception is raised.

    Parameters
    ----------
    dt:
        The fixed instant to return on every ``utc_now()`` call inside the
        block. Naive datetimes are interpreted as UTC.

    Yields
    ------
    FrozenClock
        The frozen clock instance so callers can advance it with
        :meth:`FrozenClock.tick` if needed.

    Example::

        from datetime import datetime, timezone
        from squash._clock import freeze_clock, utc_now

        fixed = datetime(2026, 5, 1, tzinfo=timezone.utc)
        with freeze_clock(fixed) as clk:
            assert utc_now() == fixed
        # After the block, utc_now() returns the real system time again.
    """
    frozen = FrozenClock(dt)
    with with_clock(frozen) as c:
        yield c  # type: ignore[misc]
