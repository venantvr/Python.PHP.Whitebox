# detectors/path_traversal.py
from detectors.base import BaseDetector


class PathTraversalDetector(BaseDetector):
    vuln_type = "path_traversal"
