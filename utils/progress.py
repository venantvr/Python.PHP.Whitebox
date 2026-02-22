# utils/progress.py - Barre de progression simple (sans dependance externe)

from __future__ import annotations

import sys
import time


class ProgressTracker:
    """Barre de progression simple pour le terminal."""

    def __init__(self, enabled: bool = True, no_color: bool = False):
        self.enabled = enabled
        self.no_color = no_color
        self._phase = ""
        self._total = 0
        self._current = 0
        self._start_time = 0.0

    def start_phase(self, label: str, total: int = 0):
        if not self.enabled:
            return
        self._phase = label
        self._total = total
        self._current = 0
        self._start_time = time.monotonic()
        self._print_progress()

    def advance(self, n: int = 1):
        if not self.enabled:
            return
        self._current += n
        self._print_progress()

    def finish_phase(self, message: str = ""):
        if not self.enabled:
            return
        elapsed = time.monotonic() - self._start_time
        sys.stderr.write(f"\r\033[K  [+] {message} ({elapsed:.1f}s)\n")
        sys.stderr.flush()

    def _print_progress(self):
        if self._total > 0:
            pct = min(100, int(self._current / self._total * 100))
            bar_width = 30
            filled = int(pct / 100 * bar_width)
            bar = "#" * filled + "." * (bar_width - filled)
            sys.stderr.write(f"\r  [{bar}] {pct}% {self._phase} ({self._current}/{self._total})")
        else:
            sys.stderr.write(f"\r  [*] {self._phase}...")
        sys.stderr.flush()
