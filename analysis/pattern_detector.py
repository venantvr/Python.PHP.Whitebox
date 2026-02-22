# analysis/pattern_detector.py - Detection par regex (secrets, crypto, configs)

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from config.schema import Severity, Confidence
from report.finding import Finding

if TYPE_CHECKING:
    from config.loader import RulesConfig


class PatternDetector:
    """Detecteur de patterns regex pour les vulns non liees au flux de donnees.

    Complementaire au TaintTracker : detecte les hardcoded secrets, algorithmes
    crypto faibles, et configurations dangereuses par matching regex ligne par
    ligne. Les patterns sont pre-compiles au __init__ pour la performance.
    Les findings produits ont detection_mode="pattern" et confidence=LOW
    (pas de preuve de flux de donnees).
    """

    def __init__(self, rules: RulesConfig):
        self.rules = rules
        self._compiled: list[tuple[re.Pattern, str, str, Severity, str, str]] = []
        self._compile_all()

    def _compile_all(self):
        # Patterns depuis les vulnerabilites avec detection_mode == "pattern"
        for vuln_type, rule in self.rules.vulnerabilities.items():
            if rule.detection_mode != "pattern":
                continue
            for p in rule.patterns:
                try:
                    compiled = re.compile(p["pattern"])
                    self._compiled.append((
                        compiled,
                        vuln_type,
                        p.get("message", rule.description),
                        rule.severity,
                        rule.cwe,
                        rule.remediation,
                    ))
                except re.error:
                    continue

        # Patterns de configuration dangereuse
        for cfg in self.rules.dangerous_configs:
            try:
                compiled = re.compile(cfg["pattern"])
                self._compiled.append((
                    compiled,
                    "dangerous_config",
                    cfg.get("message", "Dangerous configuration"),
                    Severity.from_str(cfg.get("severity", "medium")),
                    cfg.get("cwe", ""),
                    "",
                ))
            except re.error:
                continue

    def scan_file(self, file_path: str, source_code: str) -> list[Finding]:
        """Scanne un fichier source ligne par ligne pour les patterns."""
        findings: list[Finding] = []
        lines = source_code.splitlines()

        for line_no, line in enumerate(lines, 1):
            for compiled, vuln_type, message, severity, cwe, remediation in self._compiled:
                if compiled.search(line):
                    findings.append(Finding(
                        vuln_type=vuln_type,
                        severity=severity,
                        confidence=Confidence.LOW,
                        cwe=cwe,
                        owasp="",
                        title=message,
                        description=message,
                        file_path=file_path,
                        line=line_no,
                        column=0,
                        code_snippet=line.strip(),
                        remediation=remediation,
                        detection_mode="pattern",
                    ))

        return findings
