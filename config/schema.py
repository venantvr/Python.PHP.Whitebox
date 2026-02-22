# config/schema.py - Enums, dataclasses et types partages

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional


class Severity(IntEnum):
    """Niveau de severite d'une vulnerabilite, utilise pour le tri, le filtrage
    et le calcul du risk score. Les poids numeriques (0-4) permettent des
    comparaisons directes : finding.severity >= Severity.HIGH."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.upper()]


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def from_str(cls, s: str) -> "Confidence":
        return cls[s.upper()]


@dataclass
class VulnRule:
    """Definition d'un type de vulnerabilite charge depuis rules.yaml.

    Deux modes de detection :
      - "taint" : le TaintTracker suit le flux de donnees des sources vers les sinks.
      - "pattern" : le PatternDetector applique les regex ligne par ligne.
    Les sinks et node_types alimentent les index inverses de RulesConfig.
    """

    vuln_type: str
    cwe: str
    owasp: str
    severity: Severity
    description: str
    remediation: str
    sinks: list[str] = field(default_factory=list)
    node_types: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    patterns: list[dict] = field(default_factory=list)
    detection_mode: str = "taint"  # "taint" or "pattern"


@dataclass
class FilterInfo:
    """Sanitizer contextuel : neutralise certaines categories de vulns mais pas toutes.

    Exemple : htmlspecialchars neutralise ["xss"] mais pas "sql_injection".
    Le TaintTracker utilise cette info pour retirer les categories neutralisees
    du TaintFact sans le supprimer completement.
    """

    name: str
    neutralizes: list[str]
    confidence: Confidence = Confidence.HIGH


@dataclass
class ScanConfig:
    """Configuration d'un scan, construite par le CLI et passee au Scanner."""

    project_path: Path
    vuln_types: list[str] = field(default_factory=list)
    rules: Optional[object] = None  # RulesConfig
    severity_min: str = "info"
    confidence_min: str = "low"
    exclude_patterns: list[str] = field(default_factory=list)
    output_path: Optional[Path] = None
    output_format: str = "terminal"
    no_color: bool = False
    baseline_path: Optional[Path] = None
    verbosity: str = "normal"  # "debug", "normal", "quiet"
    show_progress: bool = True
