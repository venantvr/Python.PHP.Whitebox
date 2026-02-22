# detectors/session_fixation.py
from detectors.base import BaseDetector
from report.finding import Finding


class SessionFixationDetector(BaseDetector):
    vuln_type = "session_fixation"

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        result = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            # Verifier si session_regenerate_id est appele
            if "session_regenerate_id" in source:
                continue
            result.append(f)
        return result
