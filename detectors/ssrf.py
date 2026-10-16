# detectors/ssrf.py
from detectors.base import BaseDetector


class SSRFDetector(BaseDetector):
    vuln_type = "ssrf"
