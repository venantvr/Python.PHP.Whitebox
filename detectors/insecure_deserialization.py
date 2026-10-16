# detectors/insecure_deserialization.py
from detectors.base import BaseDetector


class InsecureDeserializationDetector(BaseDetector):
    vuln_type = "insecure_deserialization"
