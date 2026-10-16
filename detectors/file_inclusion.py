# detectors/file_inclusion.py
from detectors.base import BaseDetector


class FileInclusionDetector(BaseDetector):
    vuln_type = "file_inclusion"
