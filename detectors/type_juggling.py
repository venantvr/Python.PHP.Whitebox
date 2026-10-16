# detectors/type_juggling.py
from detectors.base import BaseDetector


class TypeJugglingDetector(BaseDetector):
    vuln_type = "type_juggling"
