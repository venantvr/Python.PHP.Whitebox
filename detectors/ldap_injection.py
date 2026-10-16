# detectors/ldap_injection.py
from detectors.base import BaseDetector


class LDAPInjectionDetector(BaseDetector):
    vuln_type = "ldap_injection"
