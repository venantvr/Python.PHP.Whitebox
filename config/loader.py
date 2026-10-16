# config/loader.py - Chargement et indexation des regles

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

import yaml

from config.schema import (
    VulnRule, FilterInfo, Severity, Confidence, SinkSpec, ValidatorInfo, RefOutput,
)

DEFAULT_RULES_PATH = str(Path(__file__).resolve().parent / "rules.yaml")


def _last_segment(name: str) -> str:
    """'\\Foo\\Bar::baz' -> 'Bar::baz' ; '\\strlen' -> 'strlen'."""
    name = name.strip()
    if "::" in name:
        cls, _, meth = name.partition("::")
        cls = cls.strip("\\").split("\\")[-1]
        return cls + "::" + meth
    return name.strip("\\").split("\\")[-1]


class RulesConfig:
    """Regles de detection chargees depuis rules.yaml et indexees pour lookup O(1).

    Index construits au chargement :
      - _function_sinks[name]      -> [SinkSpec]   fonctions globales (mysqli_query)
      - _any_method_sinks[method]  -> [SinkSpec]   "->query" : methode sur n'importe quel objet
      - _class_method_sinks[(Class, method)] -> [SinkSpec]   "wpdb::query", "DB::select"
      - _new_sinks[Class]          -> [SinkSpec]   "new SimpleXMLElement"
      - _node_type_to_vuln         -> VulnRule     echo_statement, include_expression ...
    Un meme nom peut etre sink de plusieurs vulns (file_get_contents : path_traversal + ssrf) ;
    la liste conserve l'ordre de declaration pour le departage.
    """

    def __init__(self, raw: dict):
        self._raw = raw
        self.sources: set[str] = set()
        self.source_functions: dict[str, Optional[tuple[int, re.Pattern]]] = {}
        self.source_methods: set[str] = set()
        self.request_object_pattern: Optional[re.Pattern] = None
        self.request_types: set[str] = set()
        self.request_methods: set[str] = set()
        self.request_properties: bool = True
        self.dangerous_server_keys: set[str] = set()
        self.propagators: set[str] = set()
        self.method_propagators: set[str] = set()
        self.safe_functions: set[str] = set()
        self.filters: dict[str, FilterInfo] = {}
        self.filter_flags: dict[str, list[str]] = {}
        self.validators: dict[str, ValidatorInfo] = {}
        self.ref_outputs: dict[str, RefOutput] = {}
        self.privilege_guards: set[str] = set()
        self.terminators: set[str] = set()
        self.assume_sanitizer_pattern: Optional[re.Pattern] = None
        self.url_hint_pattern: Optional[re.Pattern] = None
        self.vulnerabilities: dict[str, VulnRule] = {}
        self.dangerous_configs: list[dict] = []
        self.taint_categories: frozenset[str] = frozenset()

        # Index inverses
        self._function_sinks: dict[str, list[SinkSpec]] = {}
        self._any_method_sinks: dict[str, list[SinkSpec]] = {}
        self._class_method_sinks: dict[tuple[str, str], list[SinkSpec]] = {}
        self._new_sinks: dict[str, list[SinkSpec]] = {}
        self._sink_to_vuln: dict[str, VulnRule] = {}
        self._node_type_to_vuln: dict[str, VulnRule] = {}

        self._build(raw)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def _categories(self, value) -> list[str]:
        """'all' -> toutes les categories taint ; liste -> liste."""
        if value is None:
            return []
        if isinstance(value, str):
            if value.lower() == "all":
                return sorted(self.taint_categories)
            return [value]
        return list(value)

    def _build(self, raw: dict):
        # Les categories de taint = toutes les vulns en mode taint (calculees d'abord,
        # car "neutralizes: all" en depend).
        vulns_raw = raw.get("vulnerabilities", {}) or {}
        self.taint_categories = frozenset(
            vt for vt, vd in vulns_raw.items()
            if (vd or {}).get("detection_mode", "taint") == "taint"
        )

        # Sources
        src = raw.get("sources", {}) or {}
        for sg in src.get("superglobals", []) or []:
            self.sources.add(sg)
        for fn in src.get("functions", []) or []:
            if isinstance(fn, dict):
                cond = fn.get("when_arg")
                self.source_functions[fn["name"]] = (
                    (int(cond[0]), re.compile(cond[1])) if cond else None
                )
            else:
                self.source_functions[fn] = None
        for m in src.get("methods", []) or []:
            self.source_methods.add(m)
        for key in src.get("dangerous_server_keys", []) or []:
            self.dangerous_server_keys.add(key)
        ro = src.get("request_objects") or {}
        if ro.get("object_pattern"):
            self.request_object_pattern = re.compile(ro["object_pattern"])
        self.request_types = set(ro.get("request_types", []) or [])
        self.request_methods = set(ro.get("methods", []) or [])
        self.request_properties = bool(ro.get("properties", True))

        # Propagators / safe
        for p in raw.get("propagators", []) or []:
            self.propagators.add(p)
        for p in raw.get("method_propagators", []) or []:
            self.method_propagators.add(p)
        for p in raw.get("safe_functions", []) or []:
            self.safe_functions.add(p)

        # Filters
        for name, info in (raw.get("filters", {}) or {}).items():
            if isinstance(info, dict):
                neutralizes = self._categories(info.get("neutralizes", []))
                conf_str = info.get("confidence", "high")
                arg = int(info.get("arg", 0))
                variadic = bool(info.get("variadic", False))
                flags_arg = info.get("flags_arg")
            else:
                neutralizes = self._categories(info)
                conf_str, arg, variadic, flags_arg = "high", 0, False, None
            key = _last_segment(name)
            self.filters[key] = FilterInfo(
                name=key,
                neutralizes=neutralizes,
                confidence=Confidence.from_str(conf_str),
                arg=arg,
                variadic=variadic,
                flags_arg=int(flags_arg) if flags_arg is not None else None,
            )
            # "Class::method" -> aussi accessible par "->method"
            if "::" in key:
                _, _, meth = key.partition("::")
                self.filters.setdefault("->" + meth, self.filters[key])

        for flag, cats in (raw.get("filter_flags", {}) or {}).items():
            self.filter_flags[flag] = self._categories(cats)

        # Validators
        for name, info in (raw.get("validators", {}) or {}).items():
            info = info or {}
            self.validators[name] = ValidatorInfo(
                name=name,
                neutralizes=self._categories(info.get("neutralizes", "all")),
                arg=int(info.get("arg", 0)),
                confidence=Confidence.from_str(info.get("confidence", "high")),
                regex_arg=info.get("regex_arg"),
            )

        # Ref outputs
        for name, info in (raw.get("ref_outputs", {}) or {}).items():
            self.ref_outputs[name] = RefOutput(
                name=name,
                from_arg=int(info["from"]),
                to_arg=int(info["to"]),
                regex_arg=info.get("regex_arg"),
            )

        self.privilege_guards = set(raw.get("privilege_guards", []) or [])
        self.terminators = set(raw.get("terminators", []) or [])

        heur = raw.get("heuristics", {}) or {}
        pat = heur.get("assume_sanitizer_pattern")
        self.assume_sanitizer_pattern = re.compile(pat) if pat else None
        pat = heur.get("url_hint_pattern")
        self.url_hint_pattern = re.compile(pat) if pat else None

        # Vulnerabilities
        for vuln_type, vdata in vulns_raw.items():
            vdata = vdata or {}
            sink_specs = [self._parse_sink(s, vuln_type) for s in vdata.get("sinks", []) or []]
            rule = VulnRule(
                vuln_type=vuln_type,
                cwe=vdata.get("cwe", ""),
                owasp=vdata.get("owasp", ""),
                severity=Severity.from_str(vdata.get("severity", "medium")),
                description=vdata.get("description", ""),
                remediation=vdata.get("remediation", ""),
                sinks=[s.name for s in sink_specs],
                sink_specs=sink_specs,
                node_types=vdata.get("node_types", []) or [],
                sanitizers=vdata.get("sanitizers", []) or [],
                patterns=vdata.get("patterns", []) or [],
                detection_mode=vdata.get("detection_mode", "taint"),
            )
            self.vulnerabilities[vuln_type] = rule

            for spec in sink_specs:
                self._index_sink(spec, rule)

            for nt in rule.node_types:
                self._node_type_to_vuln.setdefault(nt, rule)

        self.dangerous_configs = raw.get("dangerous_configs", []) or []

    def _parse_sink(self, entry, vuln_type: str) -> SinkSpec:
        if isinstance(entry, dict):
            name = entry["name"]
            spec = SinkSpec(
                name=name,
                vuln_type=vuln_type,
                args=[int(a) for a in entry["args"]] if entry.get("args") is not None else None,
                max_args=entry.get("max_args"),
                when_arg=(int(entry["when_arg"][0]), entry["when_arg"][1]) if entry.get("when_arg") else None,
                safe_if_arg=(int(entry["safe_if_arg"][0]), entry["safe_if_arg"][1]) if entry.get("safe_if_arg") else None,
                confidence=Confidence.from_str(entry.get("confidence", "high")),
            )
        else:
            name = str(entry)
            spec = SinkSpec(name=name, vuln_type=vuln_type)

        if name.startswith("new "):
            spec.kind = "new"
            spec.class_name = _last_segment(name[4:].strip())
            spec.short_name = spec.class_name
        elif name.startswith("->"):
            spec.kind = "any_method"
            spec.short_name = name[2:]
        elif "::" in name:
            cls, _, meth = _last_segment(name).partition("::")
            spec.kind = "method"
            spec.class_name = cls
            spec.short_name = meth
        else:
            spec.kind = "function"
            spec.short_name = _last_segment(name)
        return spec

    def _index_sink(self, spec: SinkSpec, rule: VulnRule):
        if spec.kind == "function":
            self._function_sinks.setdefault(spec.short_name, []).append(spec)
            self._sink_to_vuln.setdefault(spec.short_name, rule)
        elif spec.kind == "any_method":
            self._any_method_sinks.setdefault(spec.short_name, []).append(spec)
            self._sink_to_vuln.setdefault("->" + spec.short_name, rule)
        elif spec.kind == "method":
            self._class_method_sinks.setdefault((spec.class_name.lower(), spec.short_name), []).append(spec)
            self._sink_to_vuln.setdefault(f"{spec.class_name}::{spec.short_name}", rule)
        elif spec.kind == "new":
            self._new_sinks.setdefault(spec.class_name.lower(), []).append(spec)
            self._sink_to_vuln.setdefault("new " + spec.class_name, rule)

    # ------------------------------------------------------------------
    # Requetes
    # ------------------------------------------------------------------

    def is_source(self, var_name: str) -> bool:
        """Verifie si un nom de variable est une source de taint ($_GET, $_POST...)."""
        base = var_name.split("[", 1)[0]
        return base in self.sources

    def is_source_function(self, func_name: str) -> bool:
        return func_name in self.source_functions

    def source_function_condition(self, func_name: str) -> Optional[tuple[int, re.Pattern]]:
        return self.source_functions.get(func_name)

    def is_propagator(self, func_name: str) -> bool:
        return func_name in self.propagators

    def is_safe_function(self, func_name: str) -> bool:
        return func_name in self.safe_functions

    def get_filter_info(self, func_name: str) -> Optional[FilterInfo]:
        return self.filters.get(func_name)

    def get_validator(self, func_name: str) -> Optional[ValidatorInfo]:
        return self.validators.get(func_name)

    def get_ref_output(self, func_name: str) -> Optional[RefOutput]:
        return self.ref_outputs.get(func_name)

    def get_sink_vuln(self, func_name: str) -> Optional[VulnRule]:
        """Retourne la (premiere) VulnRule si func_name est un sink (compat)."""
        return self._sink_to_vuln.get(func_name)

    def get_function_sinks(self, func_name: str) -> list[SinkSpec]:
        return self._function_sinks.get(func_name, [])

    def get_method_sinks(self, method: str, class_name: Optional[str] = None) -> list[SinkSpec]:
        """Sinks applicables a $obj->method(). Les sinks lies a une classe connue
        passent en premier, puis les sinks '->method' valables sur tout objet."""
        result: list[SinkSpec] = []
        if class_name:
            result.extend(self._class_method_sinks.get((class_name.lower(), method), []))
        result.extend(self._any_method_sinks.get(method, []))
        return result

    def get_class_method_sinks(self, class_name: str, method: str) -> list[SinkSpec]:
        return self._class_method_sinks.get((class_name.lower(), method), [])

    def class_names_for_method(self, method: str) -> list[str]:
        """Classes declarant `method` comme sink (pour le matching par nom de variable)."""
        return [cls for (cls, m) in self._class_method_sinks if m == method]

    def get_new_sinks(self, class_name: str) -> list[SinkSpec]:
        return self._new_sinks.get(class_name.lower(), [])

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


def load_rules(path: Optional[str] = None) -> RulesConfig:
    """Charge les regles depuis un fichier YAML (par defaut config/rules.yaml du projet)."""
    if path is None:
        path = DEFAULT_RULES_PATH
    elif not os.path.isabs(path) and not os.path.exists(path):
        # Chemin relatif absent du CWD : essayer relativement au projet.
        candidate = Path(__file__).resolve().parent.parent / path
        if candidate.exists():
            path = str(candidate)
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
        for p in rule.patterns:
            try:
                re.compile(p["pattern"])
            except re.error as e:
                errors.append(f"{vuln_type}: invalid pattern {p.get('pattern')!r}: {e}")
    for name, f in rules.filters.items():
        unknown = set(f.neutralizes) - set(rules.taint_categories)
        if unknown:
            errors.append(f"filter {name}: unknown categories {sorted(unknown)}")
    return errors
