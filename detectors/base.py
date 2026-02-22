# detectors/base.py - BaseDetector ABC

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from config.schema import Severity, Confidence
from report.finding import Finding
from analysis.taint_state import TaintFact, TraceStep

if TYPE_CHECKING:
    from config.loader import RulesConfig


class BaseDetector(ABC):
    """Classe abstraite pour les 16 detecteurs de vulnerabilites.

    Chaque detecteur specialise filtre les findings bruts produits par le
    TaintTracker et le PatternDetector, verifie la pertinence contextuelle
    (sanitizers corrects, sink attendu), et enrichit les metadata (CWE, OWASP,
    remediation).

    Le flow est : TaintTracker produit les findings bruts -> chaque detecteur
    appelle detect() pour filtrer par vuln_type, verifier la sanitization, et
    retourner les findings valides via build_finding().

    Pour creer un nouveau detecteur :
      1. Heriter de BaseDetector
      2. Definir vuln_type (ex: "sql_injection")
      3. Implementer detect() qui filtre par vuln_type et appelle
         is_properly_sanitized() pour eliminer les faux positifs
      4. Enregistrer dans detectors/__init__.py REGISTRY
    """

    vuln_type: str = ""
    default_severity: Severity = Severity.MEDIUM
    cwe: str = ""
    owasp: str = ""

    def __init__(self, rules: "RulesConfig"):
        self.rules = rules
        vuln_rule = rules.vulnerabilities.get(self.vuln_type)
        if vuln_rule:
            self.default_severity = vuln_rule.severity
            self.cwe = vuln_rule.cwe
            self.owasp = vuln_rule.owasp
            self.sinks = set(vuln_rule.sinks)
            self.sanitizers = set(vuln_rule.sanitizers)
            self.description = vuln_rule.description
            self.remediation = vuln_rule.remediation
        else:
            self.sinks = set()
            self.sanitizers = set()
            self.description = ""
            self.remediation = ""

    @abstractmethod
    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        """Filtre et enrichit les findings pour ce type de vuln."""
        ...

    def is_properly_sanitized(self, finding: Finding) -> bool:
        """Verifie si les sanitizers appliques couvrent ce type de vuln."""
        for step in finding.data_flow:
            if "Sanitized by" in step.description:
                func_name = step.description.replace("Sanitized by ", "").rstrip("()")
                filter_info = self.rules.get_filter_info(func_name)
                if filter_info and self.vuln_type in filter_info.neutralizes:
                    return True
        return False

    def build_finding(self, finding: Finding, **overrides) -> Finding:
        """Construit un Finding enrichi avec les metadata du detecteur."""
        return Finding(
            vuln_type=overrides.get("vuln_type", finding.vuln_type),
            severity=overrides.get("severity", finding.severity),
            confidence=overrides.get("confidence", finding.confidence),
            cwe=overrides.get("cwe", self.cwe or finding.cwe),
            owasp=overrides.get("owasp", self.owasp or finding.owasp),
            title=overrides.get("title", finding.title),
            description=overrides.get("description", finding.description),
            file_path=finding.file_path,
            line=finding.line,
            column=finding.column,
            sink_function=finding.sink_function,
            source_variable=finding.source_variable,
            code_snippet=finding.code_snippet,
            data_flow=finding.data_flow,
            remediation=overrides.get("remediation", self.remediation or finding.remediation),
            detection_mode=finding.detection_mode,
        )
