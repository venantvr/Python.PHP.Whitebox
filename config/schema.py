# config/schema.py - Enums, dataclasses et types partages

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional


class Severity(IntEnum):
    """Niveau de severite d'une vulnerabilite, utilise pour le tri, le filtrage
    et le calcul du risk score. Les poids numeriques (0-4) permettent des
    comparaisons directes : finding.severity >= Severity.HIGH."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.upper()]


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def from_str(cls, s: str) -> "Confidence":
        return cls[s.upper()]


@dataclass
class SinkSpec:
    """Un sink individuel (fonction, methode, constructeur) et ses contraintes.

    name        : nom tel qu'ecrit dans rules.yaml ("mysqli_query", "wpdb::query",
                  "->query", "DB::select", "new SimpleXMLElement").
    args        : indices des arguments dangereux (None = tous).
    max_args    : le sink n'est actif que si l'appel a au plus N arguments
                  (ex: parse_str a 1 argument, print_r sans 2e argument).
    when_arg    : (index, regex) - sink actif uniquement si l'argument index
                  matche la regex (ex: curl_setopt avec CURLOPT_URL).
    safe_if_arg : (index, regex) - sink desactive si l'argument matche
                  (ex: unserialize avec allowed_classes => false).
    confidence  : confiance du sink lui-meme.
    """

    name: str
    vuln_type: str
    args: Optional[list[int]] = None
    max_args: Optional[int] = None
    when_arg: Optional[tuple[int, str]] = None
    safe_if_arg: Optional[tuple[int, str]] = None
    confidence: Confidence = Confidence.HIGH
    # Derives au chargement
    kind: str = "function"          # "function" | "method" | "static" | "new" | "any_method"
    class_name: str = ""            # pour method/static/new
    short_name: str = ""            # nom de fonction/methode sans classe ni namespace


@dataclass
class VulnRule:
    """Definition d'un type de vulnerabilite charge depuis rules.yaml.

    Deux modes de detection :
      - "taint" : le TaintTracker suit le flux de donnees des sources vers les sinks.
      - "pattern" : le PatternDetector applique les regex ligne par ligne.
    Les sinks et node_types alimentent les index inverses de RulesConfig.
    """

    vuln_type: str
    cwe: str
    owasp: str
    severity: Severity
    description: str
    remediation: str
    sinks: list[str] = field(default_factory=list)          # noms (compat)
    sink_specs: list[SinkSpec] = field(default_factory=list)
    node_types: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    patterns: list[dict] = field(default_factory=list)
    detection_mode: str = "taint"  # "taint" or "pattern"


@dataclass
class FilterInfo:
    """Sanitizer contextuel : neutralise certaines categories de vulns mais pas toutes.

    Exemple : htmlspecialchars neutralise ["xss"] mais pas "sql_injection".
    Le TaintTracker utilise cette info pour retirer les categories neutralisees
    de chaque label du TaintFact sans supprimer le taint entierement.

    arg      : index de l'argument filtre (ex: 1 pour mysqli_real_escape_string($conn, $s)).
    variadic : le filtre s'applique a tous les arguments a partir de `arg`
               (ex: $wpdb->prepare($format, ...$values)).
    flags_arg: index de l'argument contenant un flag FILTER_* (filter_var, filter_input) ;
               les categories neutralisees dependent alors du flag.
    """

    name: str
    neutralizes: list[str]
    confidence: Confidence = Confidence.HIGH
    arg: int = 0
    variadic: bool = False
    flags_arg: Optional[int] = None


@dataclass
class ValidatorInfo:
    """Fonction de validation booleenne utilisee comme garde dans une condition.

    if (is_numeric($id)) { ... }   -> $id neutralise dans la branche then
    if (!ctype_digit($id)) exit;   -> $id neutralise apres le if
    """

    name: str
    neutralizes: list[str]
    arg: int = 0
    confidence: Confidence = Confidence.HIGH
    regex_arg: Optional[int] = None   # preg_match : la regex doit etre "stricte"


@dataclass
class RefOutput:
    """Fonction ecrivant son resultat dans un argument par reference.

    preg_match($re, $subject, $matches) : $matches herite du taint de $subject.
    """

    name: str
    from_arg: int
    to_arg: int
    regex_arg: Optional[int] = None    # si regex stricte -> sortie neutralisee


@dataclass
class ScanConfig:
    """Configuration d'un scan, construite par le CLI et passee au Scanner."""

    project_path: Path
    vuln_types: list[str] = field(default_factory=list)
    rules: Optional[object] = None  # RulesConfig
    severity_min: str = "info"
    confidence_min: str = "low"
    exclude_patterns: list[str] = field(default_factory=list)
    output_path: Optional[Path] = None
    output_format: str = "terminal"
    no_color: bool = False
    baseline_path: Optional[Path] = None
    verbosity: str = "normal"  # "debug", "normal", "quiet"
    show_progress: bool = True
    extensions: Optional[list[str]] = None
    taint_params: bool = False   # considerer les parametres des fonctions jamais appelees comme tainted
