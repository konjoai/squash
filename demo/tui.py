"""demo/tui.py — Squash-branded terminal UI helpers.

Squash logo palette (matches the wordmark logo and the website theme):

    bg          #0a121e   deep navy — terminal background, panels
    bg-elev     #11192a   slightly lighter navy — cards
    accent      #3fc66d   squash green — primary actions, banner, "✓"
    accent-2    #5dd9ff   cyan — secondary highlights
    ink         #e4e8ee   off-white — body text
    ink-dim     #7a8294   gray — labels, captions
    warn        #f7b955   amber — warnings
    bad         #ff6b8a   rose — errors

Used by ``demo/demo.py`` for the v3 Bulletproof TUI walkthrough — the
flow that must read like a TUI, not a wall of print().

Make it Konjo.
"""

from __future__ import annotations

import shutil
import sys
import time
from typing import Iterable


SQUASH_GREEN = "#3fc66d"
SQUASH_CYAN = "#5dd9ff"
SQUASH_NAVY = "#0a121e"
SQUASH_WARN = "#f7b955"
SQUASH_BAD = "#ff6b8a"
SQUASH_INK = "#e4e8ee"
SQUASH_DIM = "#7a8294"


_BANNER_LINES = [
    "                                                            ",
    "   ███████╗ ██████╗ ██╗   ██╗ █████╗ ███████╗██╗  ██╗      ",
    "   ██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██║  ██║      ",
    "   ███████╗██║   ██║██║   ██║███████║███████╗███████║      ",
    "   ╚════██║██║▄▄ ██║██║   ██║██╔══██║╚════██║██╔══██║      ",
    "   ███████║╚██████╔╝╚██████╔╝██║  ██║███████║██║  ██║      ",
    "   ╚══════╝ ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝      ",
    "                                                            ",
]


def _lerp_hex(a: str, b: str, t: float) -> str:
    """Linear-interpolate two #rrggbb colours; return #rrggbb."""
    a = a.lstrip("#"); b = b.lstrip("#")
    ar, ag, ab = int(a[0:2], 16), int(a[2:4], 16), int(a[4:6], 16)
    br, bg, bb = int(b[0:2], 16), int(b[2:4], 16), int(b[4:6], 16)
    r = round(ar + (br - ar) * t)
    g = round(ag + (bg - ag) * t)
    b_ = round(ab + (bb - ab) * t)
    return f"#{r:02x}{g:02x}{b_:02x}"


def gradient_banner(console=None) -> None:
    """Render the SQUASH ASCII banner with a green→cyan gradient.

    Falls back gracefully when rich is not present.
    """
    if console is None:
        try:
            from rich.console import Console
            console = Console(width=110)
        except ImportError:
            print("\n".join(_BANNER_LINES))
            print("  squash violations, not velocity.\n")
            return

    from rich.text import Text

    out = Text()
    for i, line in enumerate(_BANNER_LINES):
        cells = max(len(line), 1)
        for j, ch in enumerate(line):
            t = (i * 0.4 + j / cells * 0.6)
            color = _lerp_hex(SQUASH_GREEN, SQUASH_CYAN, min(1.0, t))
            out.append(ch, style=color)
        out.append("\n")
    console.print(out)
    console.print(Text("  squash violations, not velocity.", style=f"bold {SQUASH_DIM}"))
    console.print(Text("  v3 · Bulletproof Edition · evidence-grade attestations.\n",
                       style=SQUASH_DIM))


def typewriter(text: str, *, delay: float = 0.012, style: str = SQUASH_INK,
               console=None, newline: bool = True) -> None:
    """Stream *text* one character at a time, in *style*."""
    if console is None:
        sys.stdout.write(text + ("\n" if newline else ""))
        sys.stdout.flush()
        return
    for ch in text:
        console.print(ch, end="", style=style, soft_wrap=True, highlight=False)
        time.sleep(delay)
    if newline:
        console.print()


SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


def thinking(label: str, *, seconds: float = 1.5, console=None) -> None:
    """Squash-themed inline spinner — overprints on \\r."""
    if console is None:
        time.sleep(seconds)
        return
    end = time.perf_counter() + seconds
    i = 0
    while time.perf_counter() < end:
        frame = SPINNER_FRAMES[i % len(SPINNER_FRAMES)]
        console.print(
            f"\r  [{SQUASH_CYAN}]{frame}[/]  [dim]{label}[/]",
            end="", soft_wrap=False, highlight=False,
        )
        time.sleep(0.06)
        i += 1
    console.print(f"\r  [{SQUASH_GREEN}]✓[/]  {label}".ljust(80))


def fill_bar(label: str, *, total: int = 30, seconds: float = 1.0,
             console=None) -> None:
    """Render a squash-green progress bar that fills over *seconds*."""
    if console is None:
        time.sleep(seconds)
        return
    end = time.perf_counter() + seconds
    last = 0
    while True:
        now = time.perf_counter()
        t = 1.0 if now >= end else 1.0 - (end - now) / seconds
        cells = round(total * t)
        if cells != last:
            filled = "█" * cells
            empty = "░" * (total - cells)
            console.print(
                f"\r  [{SQUASH_GREEN}]{filled}[/][{SQUASH_DIM}]{empty}[/]  "
                f"[bold]{int(t * 100):>3}%[/]  [dim]{label}[/]",
                end="", soft_wrap=False, highlight=False,
            )
            last = cells
        if t >= 1.0:
            break
        time.sleep(0.02)
    console.print()


def panel_title(idx: int, total: int, title: str, blurb: str, *, console=None) -> None:
    if console is None:
        print(f"\n--- ({idx}/{total}) {title} ---")
        print(f"    {blurb}\n")
        return
    from rich.panel import Panel
    from rich.text import Text

    head = Text()
    head.append(f"  ({idx}/{total})  ", style=f"bold {SQUASH_DIM}")
    head.append(title.upper(), style=f"bold {SQUASH_GREEN}")
    body = Text(blurb, style=SQUASH_DIM)
    console.print()
    console.print(Panel.fit(
        Text.assemble(head, "\n", body),
        border_style=SQUASH_GREEN, padding=(0, 1),
    ))


def side_by_side_compare(a_label: str, b_label: str,
                         rows: Iterable[tuple[str, str, str]],
                         *, console=None, winner: str = "") -> None:
    """Render a 3-column "metric | a | b" comparison table."""
    if console is None:
        for k, a, b in rows:
            print(f"    {k:<24} {a:<26} {b:<26}")
        return
    from rich.table import Table
    from rich.text import Text

    t = Table(border_style=SQUASH_DIM, header_style=f"bold {SQUASH_GREEN}",
              show_lines=False)
    t.add_column("metric", style=SQUASH_DIM, no_wrap=True)
    a_style = f"bold {SQUASH_GREEN}" if winner == a_label else SQUASH_INK
    b_style = f"bold {SQUASH_GREEN}" if winner == b_label else SQUASH_INK
    t.add_column(a_label, style=a_style)
    t.add_column(b_label, style=b_style)
    for k, a, b in rows:
        t.add_row(k, a, b)
    console.print(t)
    if winner:
        console.print(
            Text("  ", justify="left").append("🏆  Winner: ",
                                              style=f"bold {SQUASH_GREEN}")
            .append(winner, style=f"bold {SQUASH_INK}")
        )


def severity_pill(severity: str) -> str:
    """Return a rich-marked-up dot for the given severity."""
    color = {
        "critical": SQUASH_BAD, "error": SQUASH_BAD,
        "warn": SQUASH_WARN, "info": SQUASH_CYAN,
    }.get(severity, SQUASH_DIM)
    return f"[{color}]●[/]"


def divider(console=None) -> None:
    if console is None:
        print("─" * 72)
        return
    width = min(110, shutil.get_terminal_size((110, 24)).columns)
    bar = ""
    for j in range(width):
        color = _lerp_hex(SQUASH_GREEN, SQUASH_CYAN, j / max(width - 1, 1))
        bar += f"[{color}]─[/]"
    console.print(bar)
