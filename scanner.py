# scanner.py - Orchestrateur du pipeline Python.PHP.Whitebox

from __future__ import annotations

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from parser.php_parser import parse_php_file
from parser.scope_analyzer import ScopeAnalyzer
from parser.include_resolver import IncludeResolver
from analysis.taint_tracker import TaintTracker, findings_from_uncalled_summaries
from analysis.cross_file_context import CrossFileContext
from analysis.pattern_detector import PatternDetector
from analysis.context_analyzer import ContextAnalyzer
from config.loader import load_rules, RulesConfig
from config.schema import Confidence
from detectors import get_enabled_detectors, get_all_detectors
from report.finding import Finding, ScanResult, compute_summary, SCANNER_VERSION
from utils.filewalker import find_php_files
from utils.progress import ProgressTracker

if TYPE_CHECKING:
    from config.schema import ScanConfig

# Les longues concatenations PHP produisent des AST profonds.
sys.setrecursionlimit(max(sys.getrecursionlimit(), 20000))


class Scanner:
    """Pipeline principal de scan Python.PHP.Whitebox.

    Phase 1: Discovery    -> Trouver tous les fichiers PHP
    Phase 2: Parsing      -> Parser chaque fichier avec tree-sitter
    Phase 3: Scoping      -> Extraire fonctions/classes/methodes
    Phase 4: Linking      -> Construire le graphe d'includes
    Phase 5: Summarizing  -> Resumes taint de toutes les fonctions (inter-procedural, inter-fichiers)
    Phase 6: Analysis     -> Taint tracking + patterns + detecteurs par fichier
    Phase 7: Reporting    -> Assemblage du resultat
    """

    def __init__(self, config: "ScanConfig"):
        self.config = config
        self.rules: RulesConfig = config.rules
        self.progress = ProgressTracker(
            enabled=config.show_progress,
            no_color=config.no_color,
        )
        self.global_context = CrossFileContext()

    def run(self) -> ScanResult:
        """Execute le scan complet et retourne le resultat."""
        start = time.monotonic()
        all_findings: list[Finding] = []
        total_lines = 0
        errors: list[dict] = []

        # Phase 1: Discovery
        self.progress.start_phase("Discovering PHP files")
        php_files = find_php_files(
            self.config.project_path,
            exclude_patterns=self.config.exclude_patterns,
            extensions=self.config.extensions,
        )
        self.progress.finish_phase(f"Found {len(php_files)} PHP files")

        if not php_files:
            return self._build_result([], 0, 0, time.monotonic() - start, errors)

        # Phase 2 + 3: Parsing + Scoping
        self.progress.start_phase("Parsing & scoping", total=len(php_files))
        parsed_files: dict[str, tuple] = {}  # path -> (tree, source)
        scope_analyzer = ScopeAnalyzer()

        for fpath in php_files:
            try:
                tree, source = parse_php_file(fpath)
                parsed_files[fpath] = (tree, source)
                total_lines += source.count("\n") + 1
                if tree.root_node.has_error:
                    errors.append({"phase": "parse", "file": fpath, "level": "warning",
                                   "error": "syntax errors in file (analysis continues on recovered AST)"})
                scopes = scope_analyzer.extract(tree, source, fpath)
                self.global_context.scope_map[fpath] = scopes
            except Exception as e:
                errors.append({"phase": "parse", "file": fpath, "level": "error", "error": str(e)})
            self.progress.advance()

        self.progress.finish_phase(f"Parsed {len(parsed_files)} files, {total_lines:,} lines")

        # Phase 4: Linking (include graph)
        self.progress.start_phase("Building include graph")
        resolver = IncludeResolver(self.config.project_path)
        for fpath, (tree, source) in parsed_files.items():
            try:
                includes = resolver.find_includes(tree, source, fpath)
                self.global_context.register_includes(fpath, includes)
            except Exception as e:
                errors.append({"phase": "linking", "file": fpath, "level": "error", "error": str(e)})
        self.progress.finish_phase("Include graph built")

        ordered_files = [f for f in self.global_context.topological_file_order(parsed_files.keys()) if f in parsed_files]

        # Phase 5: Function summaries (toutes les fonctions du projet, avant l'analyse)
        self.progress.start_phase("Summarizing functions", total=len(ordered_files))
        for fpath in ordered_files:
            tree, source = parsed_files[fpath]
            try:
                TaintTracker(source, tree, fpath, self.rules, self.global_context).analyze(summaries_only=True)
            except RecursionError:
                errors.append({"phase": "summary", "file": fpath, "level": "warning", "error": "AST too deep, summaries skipped"})
            except Exception as e:
                errors.append({"phase": "summary", "file": fpath, "level": "error", "error": str(e)})
            self.progress.advance()
        self.progress.finish_phase(f"Summarized {len(self.global_context.all_summaries())} functions")

        # Phase 6: Analysis + Detection
        self.progress.start_phase("Analyzing", total=len(ordered_files))

        if self.config.vuln_types:
            detectors = get_enabled_detectors(self.config.vuln_types, self.rules)
        else:
            detectors = get_all_detectors(self.rules)
        detector_types = {d.vuln_type for d in detectors}

        pattern_detector = PatternDetector(self.rules)
        context_analyzer = ContextAnalyzer()

        for fpath in ordered_files:
            tree, source = parsed_files[fpath]
            try:
                tracker = TaintTracker(
                    source_code=source,
                    tree=tree,
                    file_path=fpath,
                    rules=self.rules,
                    global_context=self.global_context,
                )
                taint_findings = tracker.analyze()
                pattern_findings = pattern_detector.scan_file(fpath, source, tree)
                file_findings = context_analyzer.refine_findings(taint_findings + pattern_findings, source)

                refined: list[Finding] = []
                for detector in detectors:
                    refined.extend(detector.detect(file_findings, fpath, source))
                # Findings de patterns sans detecteur dedie (ex: dangerous_config si filtre par type)
                for f in file_findings:
                    if f.detection_mode == "pattern" and f.vuln_type not in detector_types \
                            and (not self.config.vuln_types or f.vuln_type in self.config.vuln_types):
                        refined.append(f)

                all_findings.extend(refined)
            except RecursionError:
                errors.append({"phase": "analysis", "file": fpath, "level": "warning", "error": "AST too deep, taint analysis skipped"})
            except Exception as e:
                errors.append({"phase": "analysis", "file": fpath, "level": "error", "error": str(e)})

            self.progress.advance()

        # Mode --taint-params : parametres des fonctions jamais appelees
        if self.config.taint_params:
            extra = findings_from_uncalled_summaries(self.global_context, self.rules)
            if self.config.vuln_types:
                extra = [f for f in extra if f.vuln_type in self.config.vuln_types]
            all_findings.extend(extra)

        all_findings = self._dedupe(all_findings)
        all_findings = self._filter_confidence(all_findings)

        self.progress.finish_phase(f"Found {len(all_findings)} potential vulnerabilities")

        elapsed = time.monotonic() - start
        return self._build_result(all_findings, len(parsed_files), total_lines, elapsed, errors)

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        """Un seul finding par (fichier, ligne, type, sink, source) ; garde la meilleure confiance."""
        best: dict[str, Finding] = {}
        order: list[str] = []
        for f in findings:
            prev = best.get(f.fingerprint)
            if prev is None:
                best[f.fingerprint] = f
                order.append(f.fingerprint)
            elif f.confidence > prev.confidence or (f.confidence == prev.confidence and len(f.data_flow) > len(prev.data_flow)):
                best[f.fingerprint] = f
        return [best[k] for k in order]

    def _filter_confidence(self, findings: list[Finding]) -> list[Finding]:
        conf_min = Confidence.from_str(self.config.confidence_min or "low")
        if conf_min <= Confidence.LOW:
            return findings
        return [f for f in findings if f.confidence >= conf_min]

    def _build_result(
        self,
        findings: list[Finding],
        files_scanned: int,
        total_lines: int,
        elapsed: float,
        errors: list[dict],
    ) -> ScanResult:
        findings = sorted(findings, key=lambda f: (-int(f.severity), -int(f.confidence), f.file_path, f.line))
        summary = compute_summary(findings, files_scanned)
        return ScanResult(
            project_path=str(self.config.project_path),
            scanner_version=SCANNER_VERSION,
            timestamp=datetime.now().isoformat(),
            scan_duration_seconds=round(elapsed, 2),
            files_scanned=files_scanned,
            total_lines=total_lines,
            findings=findings,
            summary=summary,
            errors=errors,
        )


def main(project_path, vuln_types=None, output_format="terminal", output_path=None,
         exclude_patterns=None, severity_min="info", no_color=False, config_path=None,
         taint_params=False, confidence_min="low", extensions=None):
    """Point d'entree simplifie pour usage direct (import scanner; scanner.main(...))."""
    from config.schema import ScanConfig, Severity

    rules = load_rules(config_path)
    if vuln_types:
        rules = rules.filter_by_types(vuln_types)

    config = ScanConfig(
        project_path=Path(project_path),
        vuln_types=vuln_types or rules.get_vuln_types(),
        rules=rules,
        severity_min=severity_min,
        confidence_min=confidence_min,
        exclude_patterns=exclude_patterns or [],
        output_path=Path(output_path) if output_path else None,
        output_format=output_format,
        no_color=no_color,
        taint_params=taint_params,
        extensions=extensions,
    )

    scanner = Scanner(config)
    result = scanner.run()

    sev_min = Severity.from_str(severity_min)
    result.findings = [f for f in result.findings if f.severity >= sev_min]
    result.summary = compute_summary(result.findings, result.files_scanned)

    from report import generate_report
    generate_report(result, output_format, output_path, no_color=no_color)

    return result
