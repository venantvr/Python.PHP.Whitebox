# analysis/context_analyzer.py - Suppression de faux positifs contextuels

from __future__ import annotations

from report.finding import Finding


class ContextAnalyzer:
    """Post-traitement pour supprimer les faux positifs contextuels.

    Intervient apres le TaintTracker et avant les detecteurs specialises.
    Regles de suppression :
      - XXE : supprime si libxml_disable_entity_loader() present dans le fichier.
      - Open redirect : supprime si le header n'est pas "Location:".
      - SQL injection : annote si un prepared statement est detecte a proximite.
    """

    def refine_findings(self, findings: list[Finding], source_code: str) -> list[Finding]:
        """Filtre et raffine les findings en fonction du contexte."""
        refined: list[Finding] = []
        source_lower = source_code.lower()

        for f in findings:
            if f.vuln_type == "xxe":
                if self._has_entity_loader_disabled(source_lower):
                    continue

            if f.vuln_type == "open_redirect":
                if not self._is_location_header(source_code, f.line):
                    continue

            if f.vuln_type == "sql_injection":
                if self._uses_prepared_statement_near(source_code, f.line):
                    f = Finding(
                        vuln_type=f.vuln_type,
                        severity=f.severity,
                        confidence=f.confidence,
                        cwe=f.cwe,
                        owasp=f.owasp,
                        title=f.title + " (possible prepared statement nearby)",
                        description=f.description,
                        file_path=f.file_path,
                        line=f.line,
                        column=f.column,
                        sink_function=f.sink_function,
                        source_variable=f.source_variable,
                        code_snippet=f.code_snippet,
                        data_flow=f.data_flow,
                        remediation=f.remediation,
                        detection_mode=f.detection_mode,
                    )

            refined.append(f)

        return refined

    def _has_entity_loader_disabled(self, source_lower: str) -> bool:
        return "libxml_disable_entity_loader" in source_lower

    def _is_location_header(self, source: str, line: int) -> bool:
        """Verifie si la ligne contient un header Location."""
        lines = source.splitlines()
        if 0 < line <= len(lines):
            return "location" in lines[line - 1].lower()
        return False

    def _uses_prepared_statement_near(self, source: str, line: int, window: int = 10) -> bool:
        """Verifie si prepare()/bindParam sont utilises a proximite."""
        lines = source.splitlines()
        start = max(0, line - 1 - window)
        end = min(len(lines), line + window)
        context = "\n".join(lines[start:end]).lower()
        return "prepare(" in context and ("bindparam" in context or "bindvalue" in context or "execute(" in context)
