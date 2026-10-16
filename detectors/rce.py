# detectors/rce.py
from detectors.base import BaseDetector


class RCEDetector(BaseDetector):
    vuln_type = "rce"
