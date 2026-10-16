# detectors/insecure_upload.py
from detectors.base import BaseDetector


class InsecureUploadDetector(BaseDetector):
    vuln_type = "insecure_upload"
