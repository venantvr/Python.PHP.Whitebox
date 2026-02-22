# detectors/type_juggling.py
from detectors.base import BaseDetector
from report.finding import Finding


class TypeJugglingDetector(BaseDetector):
    vuln_type = "type_juggling"

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        result = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            result.append(f)
        return result
