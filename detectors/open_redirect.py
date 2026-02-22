# detectors/open_redirect.py
from detectors.base import BaseDetector
from report.finding import Finding


class OpenRedirectDetector(BaseDetector):
    vuln_type = "open_redirect"

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        result = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            # Verifier que c'est bien un header Location
            if f.sink_function == "header":
                if "location" in f.code_snippet.lower():
                    result.append(f)
            else:
                result.append(f)
        return result
