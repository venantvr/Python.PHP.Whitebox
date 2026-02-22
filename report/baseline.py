# report/baseline.py - Comparaison avec un scan precedent (baseline)

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from report.finding import Finding


class BaselineComparator:
    """Compare les findings actuels avec un baseline (scan precedent).

    Permet d'afficher uniquement les *nouveaux* findings,
    en comparant les fingerprints.
    """

    def __init__(self, baseline_path: Union[str, Path]):
        self.baseline_path = Path(baseline_path)
        self._baseline_fingerprints: set[str] = set()
        self._load_baseline()

    def _load_baseline(self) -> None:
        """Charge les fingerprints depuis le fichier baseline JSON."""
        if not self.baseline_path.is_file():
            return

        try:
            data = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return

        # Support SARIF format (runs[0].results[].fingerprints)
        if "runs" in data:
            for run in data.get("runs", []):
                for result in run.get("results", []):
                    fps = result.get("fingerprints", {})
                    for fp in fps.values():
                        self._baseline_fingerprints.add(fp)
            return

        # Support flat format (findings[].fingerprint)
        for finding in data.get("findings", []):
            fp = finding.get("fingerprint", "")
            if fp:
                self._baseline_fingerprints.add(fp)

    def filter_new(self, findings: list[Finding]) -> list[Finding]:
        """Retourne uniquement les findings absents du baseline."""
        if not self._baseline_fingerprints:
            return findings
        return [
            f for f in findings
            if f.fingerprint not in self._baseline_fingerprints
        ]

    @property
    def baseline_count(self) -> int:
        return len(self._baseline_fingerprints)
