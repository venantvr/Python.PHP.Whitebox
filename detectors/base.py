# detectors/base.py - BaseDetector ABC + GenericDetector

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from config.schema import Severity
from report.finding import Finding

if TYPE_CHECKING:
    from config.loader import RulesConfig


class BaseDetector(ABC):
    """Classe de base des detecteurs de vulnerabilites.

    Le TaintTracker garantit deja, label par label, qu'un finding n'est emis
    que si la categorie de vuln est encore dangereuse apres les sanitizers.
    Les detecteurs servent donc a :
      - filtrer les findings par type (un detecteur = un vuln_type),
      - appliquer des regles contextuelles specifiques (ex: commentaires pour
        les secrets, flags libxml pour XXE),
      - enrichir les metadata (CWE, OWASP, remediation).

    Pour creer un detecteur specialise :
      1. Heriter de BaseDetector, definir vuln_type
      2. Surcharger accept(finding, source) -> bool (ou detect() entierement)
      3. L'enregistrer dans detectors/__init__.py REGISTRY
    Les types declares dans rules.yaml sans classe dediee sont pris en charge
    par GenericDetector.
    """

    vuln_type: str = ""
    default_severity: Severity = Severity.MEDIUM
    cwe: str = ""
    owasp: str = ""

    def __init__(self, rules: "RulesConfig", vuln_type: str = ""):
        self.rules = rules
        if vuln_type:
            self.vuln_type = vuln_type
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

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        """Filtre les findings de ce type et applique accept()."""
        result: list[Finding] = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            if not self.accept(f, source):
                continue
            result.append(self.enrich(f))
        return result

    def accept(self, finding: Finding, source: str) -> bool:
        """Regle contextuelle specifique ; True par defaut."""
        return not self.is_properly_sanitized(finding)

    def is_properly_sanitized(self, finding: Finding) -> bool:
        """Compat : le TaintTracker ne produit que des findings non neutralises.

        Un finding sans trace (cree a la main) est verifie via sanitizers_applied :
        s'il ne contient que des labels neutralises pour ce type, il est ignore.
        """
        if finding.detection_mode != "taint" or finding.data_flow:
            return False
        for name in finding.sanitizers_applied:
            info = self.rules.get_filter_info(name)
            if info and self.vuln_type in info.neutralizes:
                return True
        return False

    def enrich(self, finding: Finding) -> Finding:
        """Complete les metadata manquantes (CWE/OWASP/remediation)."""
        if finding.cwe and finding.owasp and finding.remediation:
            return finding
        return self.build_finding(finding)

    def build_finding(self, finding: Finding, **overrides) -> Finding:
        """Construit un Finding enrichi avec les metadata du detecteur."""
        return Finding(
            vuln_type=overrides.get("vuln_type", finding.vuln_type),
            severity=overrides.get("severity", finding.severity),
            confidence=overrides.get("confidence", finding.confidence),
            cwe=overrides.get("cwe", finding.cwe or self.cwe),
            owasp=overrides.get("owasp", finding.owasp or self.owasp),
            title=overrides.get("title", finding.title),
            description=overrides.get("description", finding.description or self.description),
            file_path=finding.file_path,
            line=finding.line,
            column=finding.column,
            sink_function=finding.sink_function,
            source_variable=finding.source_variable,
            code_snippet=finding.code_snippet,
            data_flow=finding.data_flow,
            remediation=overrides.get("remediation", finding.remediation or self.remediation),
            detection_mode=finding.detection_mode,
            function_name=finding.function_name,
            tags=list(finding.tags),
            sanitizers_applied=list(finding.sanitizers_applied),
        )


class GenericDetector(BaseDetector):
    """Detecteur par defaut pour tout vuln_type declare dans rules.yaml."""

    def __init__(self, rules: "RulesConfig", vuln_type: str):
        super().__init__(rules, vuln_type)
