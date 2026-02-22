# detectors/__init__.py - Registre des detecteurs

from __future__ import annotations

from typing import TYPE_CHECKING

from detectors.base import BaseDetector
from detectors.sql_injection import SQLInjectionDetector
from detectors.xss import XSSDetector
from detectors.rce import RCEDetector
from detectors.code_injection import CodeInjectionDetector
from detectors.file_inclusion import FileInclusionDetector
from detectors.path_traversal import PathTraversalDetector
from detectors.insecure_upload import InsecureUploadDetector
from detectors.insecure_deserialization import InsecureDeserializationDetector
from detectors.ssrf import SSRFDetector
from detectors.xxe import XXEDetector
from detectors.open_redirect import OpenRedirectDetector
from detectors.ldap_injection import LDAPInjectionDetector
from detectors.crypto_weakness import CryptoWeaknessDetector
from detectors.hardcoded_secrets import HardcodedSecretsDetector
from detectors.session_fixation import SessionFixationDetector
from detectors.type_juggling import TypeJugglingDetector

if TYPE_CHECKING:
    from config.loader import RulesConfig

REGISTRY: dict[str, type[BaseDetector]] = {
    "sql_injection": SQLInjectionDetector,
    "xss": XSSDetector,
    "rce": RCEDetector,
    "code_injection": CodeInjectionDetector,
    "file_inclusion": FileInclusionDetector,
    "path_traversal": PathTraversalDetector,
    "insecure_upload": InsecureUploadDetector,
    "insecure_deserialization": InsecureDeserializationDetector,
    "ssrf": SSRFDetector,
    "xxe": XXEDetector,
    "open_redirect": OpenRedirectDetector,
    "ldap_injection": LDAPInjectionDetector,
    "crypto_weakness": CryptoWeaknessDetector,
    "hardcoded_secrets": HardcodedSecretsDetector,
    "session_fixation": SessionFixationDetector,
    "type_juggling": TypeJugglingDetector,
}


def get_enabled_detectors(vuln_types: list[str], rules: "RulesConfig") -> list[BaseDetector]:
    """Retourne les detecteurs actifs pour les types demandes."""
    detectors = []
    for vt in vuln_types:
        cls = REGISTRY.get(vt)
        if cls:
            detectors.append(cls(rules))
    return detectors


def get_all_detectors(rules: "RulesConfig") -> list[BaseDetector]:
    """Retourne tous les detecteurs disponibles."""
    return [cls(rules) for cls in REGISTRY.values()]
