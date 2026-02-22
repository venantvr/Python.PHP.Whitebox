# report/finding.py - Finding, ScanResult, ScanSummary

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from config.schema import Severity, Confidence
from analysis.taint_state import TraceStep


@dataclass
class Finding:
    """Une vulnerabilite detectee avec trace de flux et metadata.

    Le fingerprint est un hash SHA-256 tronque calcule automatiquement a partir
    du fichier, ligne, sink, source et type de vuln. Il sert de cle stable pour
    la comparaison baseline (ignorer les findings deja connus entre deux scans).
    """
    vuln_type: str
    severity: Severity
    confidence: Confidence
    cwe: str
    owasp: str
    title: str
    description: str
    file_path: str
    line: int
    column: int = 0
    sink_function: str = ""
    source_variable: str = ""
    code_snippet: str = ""
    data_flow: list[TraceStep] = field(default_factory=list)
    remediation: str = ""
    detection_mode: str = "taint"
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        data = f"{self.file_path}:{self.line}:{self.sink_function}:{self.source_variable}:{self.vuln_type}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


@dataclass
class ScanSummary:
    """Resume d'un scan."""
    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_vuln_type: dict[str, int] = field(default_factory=dict)
    by_confidence: dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0
    files_with_findings: int = 0
    files_clean: int = 0


@dataclass
class ScanResult:
    """Resultat complet d'un scan."""
    project_path: str = ""
    scanner_version: str = "1.0.0"
    timestamp: str = ""
    scan_duration_seconds: float = 0.0
    files_scanned: int = 0
    total_lines: int = 0
    findings: list[Finding] = field(default_factory=list)
    summary: Optional[ScanSummary] = None
    errors: list[dict] = field(default_factory=list)


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 0.5,
    Severity.INFO: 0.1,
}

CONFIDENCE_WEIGHTS = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.6,
    Confidence.LOW: 0.3,
}


def compute_summary(findings: list[Finding], files_scanned: int) -> ScanSummary:
    """Calcule les stats agregees et le risk score (0-100).

    Le risk score est la moyenne ponderee (severity * confidence) normalisee
    sur 100. Un score eleve signifie des findings a la fois severes et fiables.
    """
    by_severity: dict[str, int] = {}
    by_vuln_type: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    files_with: set[str] = set()

    for f in findings:
        sev = f.severity.name.lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_vuln_type[f.vuln_type] = by_vuln_type.get(f.vuln_type, 0) + 1
        conf = f.confidence.name.lower()
        by_confidence[conf] = by_confidence.get(conf, 0) + 1
        files_with.add(f.file_path)

    raw_score = sum(
        SEVERITY_WEIGHTS.get(f.severity, 1.0) * CONFIDENCE_WEIGHTS.get(f.confidence, 0.5)
        for f in findings
    )
    risk_score = min(100.0, (raw_score / max(len(findings), 1)) * 10) if findings else 0.0

    return ScanSummary(
        total_findings=len(findings),
        by_severity=by_severity,
        by_vuln_type=by_vuln_type,
        by_confidence=by_confidence,
        risk_score=round(risk_score, 1),
        files_with_findings=len(files_with),
        files_clean=files_scanned - len(files_with),
    )
