# analysis/taint_state.py - Structures de donnees pour le taint tracking

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Optional


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
    """Origine immutable d'un taint.

    Chaque label represente une source de donnees non fiable (ex: $_GET['id'])
    et les categories de vulns pour lesquelles elle est dangereuse. Un TaintFact
    peut porter plusieurs labels lorsque des sources sont combinees (concatenation,
    merge de branches).
    """
    source_type: str          # "user_input", "database", "file", "environment"
    source_var: str           # ex: "$_GET['id']"
    source_file: str = ""
    source_line: int = 0
    vuln_categories: frozenset = field(default_factory=frozenset)


@dataclass
class TaintFact:
    """Etat de taint d'une variable ou expression.

    Porte les labels d'origine, les filtres deja appliques, et la trace de
    propagation complete. La methode is_dangerous_for(vuln_type) determine si
    le taint est encore actif pour une categorie donnee en soustrayant les
    categories neutralisees par les filtres.

    Exemple : apres htmlspecialchars(), le fait est toujours dangerous_for("sql_injection")
    mais plus pour "xss".
    """
    labels: set[TaintLabel] = field(default_factory=set)
    filters_applied: dict[str, set[str]] = field(default_factory=dict)
    trace: list[TraceStep] = field(default_factory=list)

    @property
    def is_tainted(self) -> bool:
        return len(self.labels) > 0

    def remaining_categories(self) -> set[str]:
        """Categories de vulns pour lesquelles ce taint est encore dangereux."""
        all_cats: set[str] = set()
        for label in self.labels:
            all_cats.update(label.vuln_categories)
        neutralized: set[str] = set()
        for cats in self.filters_applied.values():
            neutralized.update(cats)
        return all_cats - neutralized

    def is_dangerous_for(self, vuln_type: str) -> bool:
        return vuln_type in self.remaining_categories()

    def apply_filter(self, filter_name: str, neutralizes: list[str]) -> "TaintFact":
        """Retourne un nouveau TaintFact avec le filtre applique."""
        new_filters = copy.deepcopy(self.filters_applied)
        new_filters[filter_name] = set(neutralizes)
        new_trace = self.trace + [TraceStep(
            file=self.trace[-1].file if self.trace else "",
            line=self.trace[-1].line if self.trace else 0,
            description=f"Sanitized by {filter_name}()"
        )]
        return TaintFact(
            labels=set(self.labels),
            filters_applied=new_filters,
            trace=new_trace,
        )

    def derive(self, description: str, file: str = "", line: int = 0,
               snippet: str = "") -> "TaintFact":
        """Cree un nouveau TaintFact derive avec une etape de trace ajoutee."""
        new_trace = self.trace + [TraceStep(
            file=file or (self.trace[-1].file if self.trace else ""),
            line=line or (self.trace[-1].line if self.trace else 0),
            description=description,
            snippet=snippet,
        )]
        return TaintFact(
            labels=set(self.labels),
            filters_applied=copy.deepcopy(self.filters_applied),
            trace=new_trace,
        )


class TaintState:
    """Etat de taint a un point du programme (mapping variable -> TaintFact).

    Represente l'environnement de taint a un point d'execution. Supporte le
    clonage (pour l'analyse de branches if/else) et le merge union (pour les
    points de jonction). Semantique conservatrice : si une variable est tainted
    dans au moins une branche, elle l'est apres le merge.
    """

    def __init__(self):
        self.variables: dict[str, TaintFact] = {}

    def clone(self) -> "TaintState":
        new = TaintState()
        for var, fact in self.variables.items():
            new.variables[var] = TaintFact(
                labels=set(fact.labels),
                filters_applied=copy.deepcopy(fact.filters_applied),
                trace=list(fact.trace),
            )
        return new

    def merge(self, other: "TaintState") -> "TaintState":
        """Union merge: si tainted dans n'importe quelle branche, tainted apres le join."""
        merged = TaintState()
        all_vars = set(self.variables) | set(other.variables)
        for var in all_vars:
            fact_a = self.variables.get(var)
            fact_b = other.variables.get(var)
            if fact_a and fact_b:
                merged.variables[var] = TaintFact(
                    labels=fact_a.labels | fact_b.labels,
                    filters_applied={**fact_a.filters_applied, **fact_b.filters_applied},
                    trace=fact_a.trace if len(fact_a.trace) >= len(fact_b.trace) else fact_b.trace,
                )
            elif fact_a:
                merged.variables[var] = TaintFact(
                    labels=set(fact_a.labels),
                    filters_applied=copy.deepcopy(fact_a.filters_applied),
                    trace=list(fact_a.trace),
                )
            elif fact_b:
                merged.variables[var] = TaintFact(
                    labels=set(fact_b.labels),
                    filters_applied=copy.deepcopy(fact_b.filters_applied),
                    trace=list(fact_b.trace),
                )
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
