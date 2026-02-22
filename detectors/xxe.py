# detectors/xxe.py
from detectors.base import BaseDetector
from report.finding import Finding


class XXEDetector(BaseDetector):
    vuln_type = "xxe"

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        result = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            # Le ContextAnalyzer filtre deja les XXE proteges
            result.append(f)
        return result
