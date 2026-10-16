# analysis/cross_file_context.py - Contexte global inter-fichiers et resumes de fonctions

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from analysis.taint_state import TaintFact, TraceStep


@dataclass
class ParamSink:
    """Un sink atteint par le parametre `param_index` d'une fonction.

    remaining : categories encore dangereuses au niveau du sink pour ce
    parametre (= toutes les categories moins les filtres appliques dans le
    corps de la fonction). Le call-site verifie que le taint reel de
    l'argument est dangereux pour `vuln_type` ET que vuln_type est dans
    `remaining`.
    """
    param_index: int
    vuln_type: str
    sink_function: str
    file: str
    line: int
    column: int
    snippet: str
    remaining: frozenset
    trace: list[TraceStep] = field(default_factory=list)
    privileged: bool = False
    confidence_penalty: int = 0


@dataclass
class FunctionSummary:
    """Resume du comportement taint d'une fonction ou methode user-defined.

    return_fact : TaintFact de la valeur de retour, pouvant contenir des labels
                  symboliques "param" (substitues au call-site) et/ou des
                  labels reels (la fonction lit $_GET directement).
    param_sinks : sinks atteints par les parametres.
    """
    name: str
    file_path: str
    class_name: Optional[str] = None
    params: list[str] = field(default_factory=list)
    start_line: int = 0
    return_fact: Optional[TaintFact] = None
    param_sinks: list[ParamSink] = field(default_factory=list)
    is_method: bool = False
    is_static: bool = False
    visibility: str = "public"

    @property
    def qualified_name(self) -> str:
        return f"{self.class_name}::{self.name}" if self.class_name else self.name

    @property
    def param_to_return(self) -> dict[int, bool]:
        """Compat : index de parametre -> propage vers le retour."""
        result: dict[int, bool] = {}
        if self.return_fact:
            for label in self.return_fact.labels:
                if label.is_param:
                    result[label.param_index] = True
        return result


class CrossFileContext:
    """Etat partage accumule entre fichiers pendant l'analyse.

    Gere trois aspects de l'analyse inter-fichiers :
      1. Graphe d'includes : quels fichiers sont inclus par quels autres.
         Permet le tri topologique pour analyser les dependances en premier.
      2. Taint exporte : chaque fichier exporte son etat de taint global,
         herite par les fichiers qui l'incluent.
      3. Resumes de fonctions : comportement taint des fonctions/methodes
         user-defined (parametre -> retour, parametre -> sink) pour l'analyse
         inter-procedurale, y compris entre fichiers non relies par include
         (autoload, hooks WordPress).
    """

    def __init__(self):
        self.include_graph: dict[str, list[str]] = {}
        self.exported_taint: dict[str, dict[str, TaintFact]] = {}
        # nom (minuscule) -> liste de resumes (plusieurs classes peuvent definir le meme nom)
        self.function_summaries: dict[str, list[FunctionSummary]] = {}
        self.scope_map: dict = {}
        self.called_names: set[str] = set()   # noms de fonctions/methodes appelees quelque part

    # --- includes ---

    def register_includes(self, file_path: str, includes: list[str]):
        self.include_graph[file_path] = includes

    def get_included_taint(self, file_path: str) -> dict[str, TaintFact]:
        """Recupere le taint exporte par les fichiers inclus."""
        result: dict[str, TaintFact] = {}
        for included in self.include_graph.get(file_path, []):
            result.update(self.exported_taint.get(included, {}))
        return result

    # --- resumes ---

    def register_function_summary(self, file_path: str, func_name: str, summary: FunctionSummary):
        key = func_name.lower()
        bucket = self.function_summaries.setdefault(key, [])
        # Remplacer un resume precedent de la meme fonction (meme fichier + classe)
        for i, existing in enumerate(bucket):
            if existing.file_path == summary.file_path and (existing.class_name or "").lower() == (summary.class_name or "").lower():
                bucket[i] = summary
                break
        else:
            bucket.append(summary)

    def get_function_summary(
        self,
        func_name: str,
        class_hint: Optional[str] = None,
        file_hint: Optional[str] = None,
        want_method: Optional[bool] = None,
    ) -> Optional[FunctionSummary]:
        """Resout un resume : meme classe > meme fichier > unique dans le projet.

        want_method=True  : ne retourner que des methodes.
        want_method=False : ne retourner que des fonctions libres.
        """
        candidates = self.function_summaries.get(func_name.lower(), [])
        if want_method is not None:
            candidates = [c for c in candidates if c.is_method == want_method]
        if not candidates:
            return None
        if class_hint:
            same_class = [c for c in candidates if (c.class_name or "").lower() == class_hint.lower()]
            if same_class:
                return same_class[0]
            # Classe connue mais pas de methode de ce nom : peut-etre heritee -> on continue
        if file_hint:
            same_file = [c for c in candidates if c.file_path == file_hint]
            if len(same_file) == 1:
                return same_file[0]
        if len(candidates) == 1:
            return candidates[0]
        # Ambigu : si tous les candidats ont le meme comportement "sans effet", on en prend un.
        return None

    def all_summaries(self) -> list[FunctionSummary]:
        return [s for bucket in self.function_summaries.values() for s in bucket]

    def register_call(self, name: str):
        self.called_names.add(name.lower())

    # --- ordre ---

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

        for f in sorted(file_set):
            visit(f)
        return order
