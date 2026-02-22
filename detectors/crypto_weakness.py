# detectors/crypto_weakness.py
from detectors.base import BaseDetector
from report.finding import Finding


class CryptoWeaknessDetector(BaseDetector):
    vuln_type = "crypto_weakness"

    def detect(self, findings: list[Finding], file_path: str, source: str) -> list[Finding]:
        result = []
        for f in findings:
            if f.vuln_type != self.vuln_type:
                continue
            result.append(f)
        return result
