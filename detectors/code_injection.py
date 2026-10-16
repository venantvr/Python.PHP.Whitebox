# detectors/code_injection.py
from detectors.base import BaseDetector


class CodeInjectionDetector(BaseDetector):
    vuln_type = "code_injection"
