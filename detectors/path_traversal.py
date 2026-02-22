# detectors/path_traversal.py
from detectors.base import BaseDetector
from report.finding import Finding


class PathTraversalDetector(BaseDetector):
    vuln_type = "path_traversal"

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        result = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            if self.is_properly_sanitized(f):
                continue
            result.append(f)
        return result
