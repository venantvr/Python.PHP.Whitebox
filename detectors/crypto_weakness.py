# detectors/crypto_weakness.py
from detectors.base import BaseDetector


class CryptoWeaknessDetector(BaseDetector):
    vuln_type = "crypto_weakness"
