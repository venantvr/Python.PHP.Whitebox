# analysis/context_analyzer.py - Ajustements contextuels des findings

from __future__ import annotations

import re
from dataclasses import replace

from config.schema import Confidence
from report.finding import Finding


class ContextAnalyzer:
    """Post-traitement contextuel, apres le TaintTracker et avant les detecteurs.

    Regles :
      - XXE : en PHP >= 8 le chargement d'entites externes est desactive par
        defaut. Confiance HIGH seulement si LIBXML_NOENT / LIBXML_DTDLOAD /
        substituteEntities / resolveExternals apparaissent dans le fichier,
        sinon LOW. Supprime si libxml_disable_entity_loader(true) est present.
      - SQL injection : annote le titre si un prepared statement avec
        parametres lies est visible a proximite (possible faux positif).
      - Findings dans des fichiers de test/fixtures : confiance reduite.
    """

    _XXE_ENABLERS = re.compile(r"LIBXML_NOENT|LIBXML_DTDLOAD|substituteEntities\s*=\s*true|resolveExternals\s*=\s*true")
    _TEST_PATH = re.compile(r"(?i)(^|/)(tests?|spec|fixtures?|examples?|samples?|demo)(/|$)")

    def refine_findings(self, findings: list[Finding], source_code: str) -> list[Finding]:
        refined: list[Finding] = []
        source_lower = source_code.lower()
        xxe_enabled = bool(self._XXE_ENABLERS.search(source_code))

        for f in findings:
            if f.vuln_type == "xxe":
                if "libxml_disable_entity_loader(true)" in source_lower.replace(" ", ""):
                    continue
                if not xxe_enabled and f.confidence > Confidence.LOW:
                    f = replace(f, confidence=Confidence.LOW,
                                title=f.title + " (entity loading not explicitly enabled: exploitable on PHP < 8 / with LIBXML_NOENT)")

            if f.vuln_type == "sql_injection" and f.detection_mode == "taint":
                if self._uses_prepared_statement_near(source_code, f.line):
                    f = replace(f, title=f.title + " (possible prepared statement nearby)")

            refined.append(f)

        return refined

    @staticmethod
    def _uses_prepared_statement_near(source: str, line: int, window: int = 6) -> bool:
        lines = source.splitlines()
        start = max(0, line - 1 - window)
        end = min(len(lines), line + window)
        context = "\n".join(lines[start:end]).lower()
        return "prepare(" in context and ("bindparam" in context or "bindvalue" in context or "bind_param" in context)
