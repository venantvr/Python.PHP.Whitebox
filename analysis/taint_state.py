# analysis/taint_state.py - Structures de donnees pour le taint tracking
#
# Les TaintFact sont IMMUTABLES par convention : toutes les operations
# (derive, apply_filter, merge) retournent un nouvel objet. Cela permet un
# clonage O(1) de l'etat (TaintState.clone copie seulement le dictionnaire).

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Iterable, Optional


@dataclass
class TraceStep:
    """Un pas dans la trace de flux de donnees (source -> step -> sink)."""
    file: str
    line: int
    column: int = 0
    description: str = ""
    snippet: str = ""


@dataclass(frozen=True)
class TaintLabel:
    """Origine immutable d'un taint, avec les categories de vulns pour lesquelles
    cette origine est ENCORE dangereuse.

    Chaque label represente une source de donnees non fiable (ex: $_GET['id']).
    Les filtres retirent des categories du label (htmlspecialchars retire "xss") :
    `vuln_categories` est donc l'ensemble *restant*. Un TaintFact peut porter
    plusieurs labels lorsque des sources sont combinees (concatenation, merge de
    branches) ; comme les categories sont portees par le label, la concatenation
    htmlspecialchars($a) . $b reste dangereuse pour xss via $b.

    source_type :
      - "user_input"  superglobales, objets requete
      - "function"    fonction source (getenv, file_get_contents('php://input'))
      - "param"       parametre symbolique d'une fonction (resume inter-procedural)
      - "environment" $_ENV / getenv / $argv (confiance plus basse)
    """
    source_type: str
    source_var: str
    source_file: str = ""
    source_line: int = 0
    vuln_categories: frozenset = field(default_factory=frozenset)
    param_index: int = -1

    @property
    def is_param(self) -> bool:
        return self.source_type == "param"

    def with_categories(self, cats: Iterable[str]) -> "TaintLabel":
        return replace(self, vuln_categories=frozenset(cats))

    def minus(self, cats: Iterable[str]) -> "TaintLabel":
        return replace(self, vuln_categories=self.vuln_categories - frozenset(cats))


@dataclass
class TaintFact:
    """Etat de taint d'une variable ou expression.

    Porte les labels d'origine (chacun avec ses categories restantes), le
    journal des filtres appliques (pour le reporting) et la trace de
    propagation complete.
    """
    labels: frozenset = field(default_factory=frozenset)
    filters_applied: dict[str, frozenset] = field(default_factory=dict)
    trace: list[TraceStep] = field(default_factory=list)

    def __post_init__(self):
        if not isinstance(self.labels, frozenset):
            self.labels = frozenset(self.labels)

    # --- Requetes ---

    @property
    def is_tainted(self) -> bool:
        """Vrai si au moins un label est encore dangereux pour une categorie."""
        return any(l.vuln_categories for l in self.labels)

    @property
    def has_labels(self) -> bool:
        return len(self.labels) > 0

    def remaining_categories(self) -> set[str]:
        """Categories de vulns pour lesquelles ce taint est encore dangereux."""
        cats: set[str] = set()
        for label in self.labels:
            cats.update(label.vuln_categories)
        return cats

    def is_dangerous_for(self, vuln_type: str) -> bool:
        return any(vuln_type in l.vuln_categories for l in self.labels)

    def real_labels(self) -> frozenset:
        return frozenset(l for l in self.labels if not l.is_param)

    def param_labels(self) -> frozenset:
        return frozenset(l for l in self.labels if l.is_param)

    @property
    def primary_source(self) -> Optional[TaintLabel]:
        """Label le plus representatif (reel avant param, dangereux avant neutralise)."""
        if not self.labels:
            return None
        return sorted(
            self.labels,
            key=lambda l: (l.is_param, not l.vuln_categories, l.source_line, l.source_var),
        )[0]

    # --- Transformations (retournent un nouveau fact) ---

    def apply_filter(self, filter_name: str, neutralizes: Iterable[str],
                     file: str = "", line: int = 0, snippet: str = "") -> "TaintFact":
        """Retourne un nouveau TaintFact avec le filtre applique a tous les labels."""
        cats = frozenset(neutralizes)
        new_filters = dict(self.filters_applied)
        new_filters[filter_name] = cats
        step = TraceStep(
            file=file or (self.trace[-1].file if self.trace else ""),
            line=line or (self.trace[-1].line if self.trace else 0),
            description=f"Sanitized by {filter_name}()",
            snippet=snippet,
        )
        return TaintFact(
            labels=frozenset(l.minus(cats) for l in self.labels),
            filters_applied=new_filters,
            trace=self.trace + [step],
        )

    def restrict_to(self, cats: Iterable[str]) -> "TaintFact":
        """Garde uniquement les categories `cats` sur chaque label."""
        cats = frozenset(cats)
        return TaintFact(
            labels=frozenset(l.with_categories(l.vuln_categories & cats) for l in self.labels),
            filters_applied=dict(self.filters_applied),
            trace=list(self.trace),
        )

    def derive(self, description: str, file: str = "", line: int = 0,
               snippet: str = "") -> "TaintFact":
        """Cree un nouveau TaintFact derive avec une etape de trace ajoutee."""
        step = TraceStep(
            file=file or (self.trace[-1].file if self.trace else ""),
            line=line or (self.trace[-1].line if self.trace else 0),
            description=description,
            snippet=snippet,
        )
        return TaintFact(
            labels=self.labels,
            filters_applied=dict(self.filters_applied),
            trace=self.trace + [step],
        )

    def with_trace(self, trace: list[TraceStep]) -> "TaintFact":
        return TaintFact(labels=self.labels, filters_applied=dict(self.filters_applied), trace=list(trace))

    def copy(self) -> "TaintFact":
        return TaintFact(labels=self.labels, filters_applied=dict(self.filters_applied), trace=list(self.trace))

    @staticmethod
    def merge(a: Optional["TaintFact"], b: Optional["TaintFact"],
              description: str = "", file: str = "", line: int = 0) -> Optional["TaintFact"]:
        """Union de deux facts : labels unis, trace la plus longue conservee."""
        if a is None:
            return b
        if b is None:
            return a
        labels = a.labels | b.labels
        filters = {**a.filters_applied, **b.filters_applied}
        trace = a.trace if len(a.trace) >= len(b.trace) else b.trace
        if description and a.is_tainted and b.is_tainted:
            trace = trace + [TraceStep(
                file=file or (trace[-1].file if trace else ""),
                line=line or (trace[-1].line if trace else 0),
                description=description,
            )]
        else:
            trace = list(trace)
        return TaintFact(labels=labels, filters_applied=filters, trace=trace)


class TaintState:
    """Etat de taint a un point du programme (mapping variable -> TaintFact).

    Supporte le clonage (analyse de branches if/else) et le merge union (points
    de jonction). Semantique conservatrice : si une variable est tainted dans
    au moins une branche, elle l'est apres le merge.

    `var_types` memorise la classe connue des variables ($x = new Foo) pour la
    resolution des sinks/methodes par classe.
    """

    __slots__ = ("variables", "var_types")

    def __init__(self):
        self.variables: dict[str, TaintFact] = {}
        self.var_types: dict[str, str] = {}

    def clone(self) -> "TaintState":
        new = TaintState()
        new.variables = dict(self.variables)
        new.var_types = dict(self.var_types)
        return new

    def merge(self, other: "TaintState") -> "TaintState":
        """Union merge: si tainted dans n'importe quelle branche, tainted apres le join."""
        merged = TaintState()
        for var in set(self.variables) | set(other.variables):
            fact_a = self.variables.get(var)
            fact_b = other.variables.get(var)
            merged.variables[var] = TaintFact.merge(fact_a, fact_b)
        for var in set(self.var_types) | set(other.var_types):
            ta, tb = self.var_types.get(var), other.var_types.get(var)
            if ta == tb or tb is None:
                merged.var_types[var] = ta
            elif ta is None:
                merged.var_types[var] = tb
        return merged

    def set_taint(self, var_key: str, fact: TaintFact):
        self.variables[var_key] = fact

    def get_taint(self, var_key: str) -> Optional[TaintFact]:
        return self.variables.get(var_key)

    def remove_taint(self, var_key: str):
        self.variables.pop(var_key, None)

    def is_tainted(self, var_key: str) -> bool:
        fact = self.variables.get(var_key)
        return fact is not None and fact.is_tainted

    def set_type(self, var_key: str, class_name: Optional[str]):
        if class_name:
            self.var_types[var_key] = class_name
        else:
            self.var_types.pop(var_key, None)

    def get_type(self, var_key: str) -> Optional[str]:
        return self.var_types.get(var_key)
