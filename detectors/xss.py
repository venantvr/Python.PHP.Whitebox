# detectors/xss.py
from detectors.base import BaseDetector


class XSSDetector(BaseDetector):
    vuln_type = "xss"
