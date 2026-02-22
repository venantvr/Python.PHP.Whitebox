# detectors/hardcoded_secrets.py
from detectors.base import BaseDetector
from report.finding import Finding


class HardcodedSecretsDetector(BaseDetector):
    vuln_type = "hardcoded_secrets"

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        result = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            # Ignorer les lignes de commentaires et les exemples
            snippet = f.code_snippet.strip()
            if snippet.startswith("//") or snippet.startswith("*") or snippet.startswith("#"):
                continue
            result.append(f)
        return result
