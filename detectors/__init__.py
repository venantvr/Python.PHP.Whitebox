# detectors/__init__.py - Registre des detecteurs
#
# Les types de vulnerabilites sont definis dans config/rules.yaml. Un detecteur
# specialise (classe ci-dessous) peut ajouter une logique contextuelle ; tout
# type sans classe dediee est pris en charge par GenericDetector, ce qui permet
# d'ajouter un type de vuln en ne touchant que le YAML.

from __future__ import annotations

from typing import TYPE_CHECKING

from detectors.base import BaseDetector, GenericDetector
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


def make_detector(vuln_type: str, rules: "RulesConfig") -> BaseDetector:
    cls = REGISTRY.get(vuln_type)
    if cls is not None:
        return cls(rules)
    return GenericDetector(rules, vuln_type)


def get_enabled_detectors(vuln_types: list[str], rules: "RulesConfig") -> list[BaseDetector]:
    """Retourne les detecteurs actifs pour les types demandes."""
    return [make_detector(vt, rules) for vt in vuln_types if vt in rules.vulnerabilities or vt in REGISTRY]


def get_all_detectors(rules: "RulesConfig") -> list[BaseDetector]:
    """Retourne un detecteur pour chaque type declare dans les regles (+ dangerous_config)."""
    types = list(rules.get_vuln_types())
    if "dangerous_config" not in types:
        types.append("dangerous_config")
    return [make_detector(vt, rules) for vt in types]
