# detectors/sql_injection.py
from detectors.base import BaseDetector
from report.finding import Finding


class SQLInjectionDetector(BaseDetector):
    vuln_type = "sql_injection"

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        result = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            if self.is_properly_sanitized(f):
                continue
            # Verifier si intval/cast a ete applique
            if any("_cast_int" in s.description or "intval" in s.description
                   for s in f.data_flow if "Sanitized" in s.description):
                continue
            result.append(f)
        return result
