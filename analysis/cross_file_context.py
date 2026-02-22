# analysis/cross_file_context.py - Contexte global inter-fichiers

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from analysis.taint_state import TaintFact


@dataclass
class FunctionSummary:
    """Resume du comportement taint d'une fonction user-defined.

    param_to_return[i] = True signifie que le parametre i propage son taint
    vers la valeur de retour. Utilise par le TaintTracker pour l'analyse
    inter-procedurale sans re-analyser le corps de la fonction.
    """
    name: str
    file_path: str
    param_to_return: dict[int, bool] = field(default_factory=dict)
    param_to_sink: dict[int, list[str]] = field(default_factory=dict)
    always_tainted_return: bool = False
    internal_sources: bool = False


class CrossFileContext:
    """Etat partage accumule entre fichiers pendant l'analyse.

    Gere trois aspects de l'analyse inter-fichiers :
      1. Graphe d'includes : quels fichiers sont inclus par quels autres.
         Permet le tri topologique pour analyser les dependances en premier.
      2. Taint exporte : chaque fichier exporte son etat de taint final,
         herite par les fichiers qui l'incluent.
      3. Summaries de fonctions : resume du comportement taint des fonctions
         user-defined pour l'analyse inter-procedurale.
    """

    def __init__(self):
        self.include_graph: dict[str, list[str]] = {}
        self.exported_taint: dict[str, dict[str, TaintFact]] = {}
        self.function_summaries: dict[tuple[str, str], FunctionSummary] = {}
        self.scope_map: dict = {}

    def register_includes(self, file_path: str, includes: list[str]):
        self.include_graph[file_path] = includes

    def register_function_summary(self, file_path: str, func_name: str, summary: FunctionSummary):
        self.function_summaries[(file_path, func_name)] = summary

    def get_included_taint(self, file_path: str) -> dict[str, TaintFact]:
        """Recupere le taint exporte par les fichiers inclus."""
        result: dict[str, TaintFact] = {}
        for included in self.include_graph.get(file_path, []):
            result.update(self.exported_taint.get(included, {}))
        return result

    def get_function_summary(self, func_name: str) -> Optional[FunctionSummary]:
        """Cherche un summary de fonction dans tous les fichiers."""
        for (fpath, fname), summary in self.function_summaries.items():
            if fname == func_name:
                return summary
        return None

    def topological_file_order(self, files) -> list:
        """Tri topologique: fichiers inclus d'abord."""
        file_set = set(str(f) for f in files)
        visited: set[str] = set()
        order: list[str] = []

        def visit(f: str):
            if f in visited:
                return
            visited.add(f)
            for dep in self.include_graph.get(f, []):
                if dep in file_set:
                    visit(dep)
            order.append(f)

        for f in file_set:
            visit(f)
        return order
