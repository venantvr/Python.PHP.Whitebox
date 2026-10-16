# detectors/sql_injection.py
from detectors.base import BaseDetector
from report.finding import Finding


class SQLInjectionDetector(BaseDetector):
    vuln_type = "sql_injection"

    def accept(self, finding: Finding, source: str) -> bool:
        if self.is_properly_sanitized(finding):
            return False
        # Requete entierement parametree : "SELECT ... WHERE id = ?" sans concatenation
        snippet = finding.code_snippet or ""
        if finding.sink_function.endswith("prepare") and "?" in snippet and "." not in snippet and "$" not in snippet.split("prepare", 1)[-1]:
            return False
        return True
