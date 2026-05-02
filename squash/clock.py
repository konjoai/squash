"""squash/clock.py — Injectable clock for evidence-grade reproducibility.

Phase G.2 — Determinism. Every call to ``datetime.now()`` in any signing
or report-emitting path replaces wallclock with an injected
:class:`Clock`. Production uses :class:`SystemClock`; tests use
:class:`FrozenClock` so that two runs over the same input produce the
same signed bytes.

Why a Clock at all
------------------

A signed cert with an embedded ``issued_at`` timestamp is non-reproducible
by construction unless the timestamp is *injected*. The audit-grade
contract is "byte-identical attestation for byte-identical input"; that
contract holds iff every contribution to the signed body is itself
deterministic given the input. The clock is the most-violated such input
in the codebase today (see ``AUDIT_BASELINE.md`` §1.2).

Public surface
--------------

* :class:`Clock` — abstract callable returning ``datetime``.
* :class:`SystemClock` — wraps ``datetime.now(timezone.utc)``; returns a
  *tz-aware* datetime with microsecond precision; **never** returns naive.
* :class:`FrozenClock` — returns the same instant every call. ``tick()``
  advances by an explicit ``timedelta`` for tests that exercise
  monotonic ordering.
* :func:`utc_now` — module-level convenience: equivalent to
  ``SystemClock()()``. Use this **only** outside signing paths (e.g. in
  registry/operational code where a wallclock is fine).
* :func:`with_clock` — context manager swapping the module-level default
  for the duration of a block. Tests rely on this.
* :func:`now` — call-the-current-clock helper. Signing paths should
  prefer accepting a ``clock: Clock`` parameter explicitly; ``now()`` is
  the documented fall-through for code that has no other path.

Konjo notes
~~~~~~~~~~~

* 건조 — one type, three callable forms (``SystemClock()``,
  ``FrozenClock(dt)``, custom ``Callable[[], datetime]``); no flags.
* ᨀᨚᨐᨚ — every signed cert constructor in this repo accepts ``clock=``;
  default is ``SystemClock()`` so existing callers never break.
* 康宙 — naive datetimes are rejected at the boundary (``canon.prepare``);
  clocks always return UTC.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
from typing import Callable, Iterator, Protocol, runtime_checkable

__all__ = [
    "Clock",
    "SystemClock",
    "FrozenClock",
    "utc_now",
    "now",
    "with_clock",
    "set_default_clock",
    "get_default_clock",
]


@runtime_checkable
class Clock(Protocol):
    """A callable that returns a tz-aware UTC :class:`datetime`."""

    def __call__(self) -> _dt.datetime: ...  # pragma: no cover - protocol


class SystemClock:
    """Wallclock UTC. Use in production code paths.

    Returns a tz-aware ``datetime`` with microsecond precision. Never
    returns naive — that would invert the contract enforced by
    :func:`squash.canon.prepare`.
    """

    __slots__ = ()

    def __call__(self) -> _dt.datetime:
        return _dt.datetime.now(_dt.timezone.utc)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "SystemClock()"


class FrozenClock:
    """Deterministic clock: returns the same instant on every call.

    For test fixtures and reproducibility tests:

    >>> from datetime import datetime, timezone
    >>> clk = FrozenClock(datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc))
    >>> clk() == clk()
    True

    Calling :meth:`tick` advances the clock for tests that need ordered
    timestamps without a real wallclock.

    Initialiser accepts naive datetime as a convenience and assumes UTC;
    every value returned is tz-aware.
    """

    __slots__ = ("_t",)

    def __init__(self, instant: _dt.datetime | None = None) -> None:
        if instant is None:
            instant = _dt.datetime(2026, 5, 1, 0, 0, 0, tzinfo=_dt.timezone.utc)
        elif instant.tzinfo is None:
            instant = instant.replace(tzinfo=_dt.timezone.utc)
        self._t = instant.astimezone(_dt.timezone.utc)

    def __call__(self) -> _dt.datetime:
        return self._t

    def tick(self, delta: _dt.timedelta) -> "FrozenClock":
        """Advance the clock by *delta* and return ``self``."""
        self._t = self._t + delta
        return self

    def set(self, instant: _dt.datetime) -> "FrozenClock":
        """Set the clock to *instant* and return ``self``."""
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=_dt.timezone.utc)
        self._t = instant.astimezone(_dt.timezone.utc)
        return self

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"FrozenClock({self._t.isoformat()})"


# ---------------------------------------------------------------------------
# Module-level default — overridable for tests via ``with_clock`` /
# ``set_default_clock``. Production code paths should prefer accepting an
# explicit ``clock=`` parameter.
# ---------------------------------------------------------------------------

_DEFAULT: Clock = SystemClock()


def get_default_clock() -> Clock:
    """Return the current module-level default clock."""
    return _DEFAULT


def set_default_clock(clock: Clock) -> None:
    """Replace the module-level default clock (rarely used outside tests)."""
    global _DEFAULT
    _DEFAULT = clock


def utc_now() -> _dt.datetime:
    """Return the current default-clock UTC datetime.

    Equivalent to ``get_default_clock()()``. Use in **operational** code
    only — signing/attestation paths should accept an explicit ``clock``
    parameter instead.
    """
    return _DEFAULT()


def now(clock: Clock | Callable[[], _dt.datetime] | None = None) -> _dt.datetime:
    """Return UTC now under the supplied *clock*, or the default if ``None``."""
    if clock is None:
        return _DEFAULT()
    return clock()


@contextlib.contextmanager
def with_clock(clock: Clock | Callable[[], _dt.datetime]) -> Iterator[Clock]:
    """Temporarily replace the module-level default clock.

    >>> from datetime import datetime, timezone
    >>> with with_clock(FrozenClock(datetime(2026, 1, 1, tzinfo=timezone.utc))) as c:
    ...     # any code in here that calls utc_now() sees the frozen value
    ...     pass
    """
    global _DEFAULT
    prev = _DEFAULT
    try:
        _DEFAULT = clock  # type: ignore[assignment]
        yield clock  # type: ignore[misc]
    finally:
        _DEFAULT = prev
