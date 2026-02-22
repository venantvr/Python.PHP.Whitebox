# detectors/insecure_upload.py
from detectors.base import BaseDetector
from report.finding import Finding


class InsecureUploadDetector(BaseDetector):
    vuln_type = "insecure_upload"

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        result = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            result.append(f)
        return result
