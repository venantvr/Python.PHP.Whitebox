# config/loader.py - Chargement et indexation des regles

from __future__ import annotations

from typing import Optional

import yaml

from config.schema import VulnRule, FilterInfo, Severity, Confidence


class RulesConfig:
    """Regles de detection chargees depuis rules.yaml et indexees pour lookup O(1).

    Construit des index inverses au chargement :
      - _sink_to_vuln : nom de fonction sink -> VulnRule (ex: "mysqli_query" -> sql_injection)
      - _node_type_to_vuln : type de noeud AST -> VulnRule (ex: "echo_statement" -> xss)

    Ces index permettent au TaintTracker de determiner en O(1) si un appel de
    fonction ou un noeud AST est un sink, un filtre, ou un propagateur.
    """

    def __init__(self, raw: dict):
        self._raw = raw
        self.sources: set[str] = set()
        self.source_functions: set[str] = set()
        self.dangerous_server_keys: set[str] = set()
        self.propagators: set[str] = set()
        self.filters: dict[str, FilterInfo] = {}
        self.vulnerabilities: dict[str, VulnRule] = {}
        self.dangerous_configs: list[dict] = []

        # Index inverses
        self._sink_to_vuln: dict[str, VulnRule] = {}
        self._node_type_to_vuln: dict[str, VulnRule] = {}

        self._build(raw)

    def _build(self, raw: dict):
        # Sources
        src = raw.get("sources", {})
        for sg in src.get("superglobals", []):
            self.sources.add(sg)
        for fn in src.get("functions", []):
            self.source_functions.add(fn)
        for key in src.get("dangerous_server_keys", []):
            self.dangerous_server_keys.add(key)

        # Propagators
        for p in raw.get("propagators", []):
            self.propagators.add(p)

        # Filters
        for name, info in raw.get("filters", {}).items():
            neutralizes = info.get("neutralizes", []) if isinstance(info, dict) else info
            conf_str = info.get("confidence", "high") if isinstance(info, dict) else "high"
            self.filters[name] = FilterInfo(
                name=name,
                neutralizes=neutralizes if isinstance(neutralizes, list) else [neutralizes],
                confidence=Confidence.from_str(conf_str),
            )

        # Vulnerabilities
        for vuln_type, vdata in raw.get("vulnerabilities", {}).items():
            rule = VulnRule(
                vuln_type=vuln_type,
                cwe=vdata.get("cwe", ""),
                owasp=vdata.get("owasp", ""),
                severity=Severity.from_str(vdata.get("severity", "medium")),
                description=vdata.get("description", ""),
                remediation=vdata.get("remediation", ""),
                sinks=vdata.get("sinks", []),
                node_types=vdata.get("node_types", []),
                sanitizers=vdata.get("sanitizers", []),
                patterns=vdata.get("patterns", []),
                detection_mode=vdata.get("detection_mode", "taint"),
            )
            self.vulnerabilities[vuln_type] = rule

            # Index inverse: sink function -> VulnRule
            for sink in rule.sinks:
                self._sink_to_vuln[sink] = rule

            # Index inverse: node type -> VulnRule
            for nt in rule.node_types:
                self._node_type_to_vuln[nt] = rule

        # Dangerous configs
        self.dangerous_configs = raw.get("dangerous_configs", [])

    def is_source(self, var_name: str) -> bool:
        """Verifie si un nom de variable est une source de taint."""
        for src in self.sources:
            if var_name.startswith(src):
                return True
        return False

    def is_source_function(self, func_name: str) -> bool:
        return func_name in self.source_functions

    def is_propagator(self, func_name: str) -> bool:
        return func_name in self.propagators

    def get_filter_info(self, func_name: str) -> Optional[FilterInfo]:
        return self.filters.get(func_name)

    def get_sink_vuln(self, func_name: str) -> Optional[VulnRule]:
        """Retourne la VulnRule si func_name est un sink."""
        return self._sink_to_vuln.get(func_name)

    def get_node_type_vuln(self, node_type: str) -> Optional[VulnRule]:
        """Retourne la VulnRule si node_type est un sink (ex: echo_statement)."""
        return self._node_type_to_vuln.get(node_type)

    def get_vuln_types(self) -> list[str]:
        return list(self.vulnerabilities.keys())

    def filter_by_types(self, types: list[str]) -> "RulesConfig":
        """Retourne une copie filtree par types de vulns."""
        filtered_raw = dict(self._raw)
        filtered_vulns = {k: v for k, v in self._raw.get("vulnerabilities", {}).items() if k in types}
        filtered_raw["vulnerabilities"] = filtered_vulns
        return RulesConfig(filtered_raw)


def load_rules(path: str = "config/rules.yaml") -> RulesConfig:
    """Charge les regles depuis un fichier YAML."""
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return RulesConfig(raw)


def validate_rules(rules: RulesConfig) -> list[str]:
    """Valide les regles chargees, retourne une liste d'erreurs."""
    errors = []
    for vuln_type, rule in rules.vulnerabilities.items():
        if not rule.cwe:
            errors.append(f"{vuln_type}: missing CWE")
        if not rule.sinks and not rule.node_types and not rule.patterns:
            errors.append(f"{vuln_type}: no sinks, node_types, or patterns defined")
    return errors
