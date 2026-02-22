# scanner.py - Orchestrateur du pipeline Python.PHP.Whitebox

from __future__ import annotations

import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from parser.php_parser import parse_php_file
from parser.scope_analyzer import ScopeAnalyzer
from parser.include_resolver import IncludeResolver
from analysis.taint_tracker import TaintTracker
from analysis.cross_file_context import CrossFileContext
from analysis.pattern_detector import PatternDetector
from analysis.context_analyzer import ContextAnalyzer
from config.loader import load_rules, RulesConfig
from detectors import get_enabled_detectors, get_all_detectors
from report.finding import Finding, ScanResult, ScanSummary, compute_summary
from utils.filewalker import find_php_files
from utils.progress import ProgressTracker

if TYPE_CHECKING:
    from config.schema import ScanConfig


class Scanner:
    """Pipeline principal de scan Python.PHP.Whitebox.

    Phase 1: Discovery   -> Trouver tous les fichiers PHP
    Phase 2: Parsing     -> Parser chaque fichier avec tree-sitter
    Phase 3: Scoping     -> Extraire fonctions/classes/methodes
    Phase 4: Linking     -> Construire le graphe d'includes
    Phase 5: Analysis    -> Taint tracking par fichier
    Phase 6: Detection   -> Detecteurs specialises + patterns
    Phase 7: Reporting   -> Assemblage du resultat
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

                # Scope extraction
                scopes = scope_analyzer.extract(tree, source, fpath)
                self.global_context.scope_map[fpath] = scopes

            except Exception as e:
                errors.append({"phase": "parse", "file": fpath, "error": str(e)})
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
                errors.append({"phase": "linking", "file": fpath, "error": str(e)})
        self.progress.finish_phase("Include graph built")

        # Phase 5 + 6: Analysis + Detection
        self.progress.start_phase("Analyzing", total=len(parsed_files))

        # Preparer les detecteurs
        if self.config.vuln_types:
            detectors = get_enabled_detectors(self.config.vuln_types, self.rules)
        else:
            detectors = get_all_detectors(self.rules)

        pattern_detector = PatternDetector(self.rules)
        context_analyzer = ContextAnalyzer()

        # Ordre topologique (fichiers inclus d'abord)
        ordered_files = self.global_context.topological_file_order(parsed_files.keys())

        for fpath in ordered_files:
            if fpath not in parsed_files:
                continue
            tree, source = parsed_files[fpath]

            try:
                # Taint analysis
                tracker = TaintTracker(
                    source_code=source,
                    tree=tree,
                    file_path=fpath,
                    rules=self.rules,
                    global_context=self.global_context,
                )
                taint_findings = tracker.analyze()

                # Pattern detection (secrets, crypto, configs)
                pattern_findings = pattern_detector.scan_file(fpath, source)

                # Combine
                file_findings = taint_findings + pattern_findings

                # Post-traitement contextuel
                file_findings = context_analyzer.refine_findings(file_findings, source)

                # Passer par les detecteurs specialises
                refined: list[Finding] = []
                for detector in detectors:
                    refined.extend(detector.detect(file_findings, fpath, source))

                # Aussi garder les findings de patterns (pas lies a un detecteur specifique)
                pattern_types = {f.vuln_type for f in pattern_findings}
                detector_types = {d.vuln_type for d in detectors}
                for f in file_findings:
                    if f.vuln_type in pattern_types and f.vuln_type not in detector_types:
                        refined.append(f)

                all_findings.extend(refined)

            except Exception as e:
                errors.append({"phase": "analysis", "file": fpath, "error": str(e)})

            self.progress.advance()

        self.progress.finish_phase(f"Found {len(all_findings)} potential vulnerabilities")

        elapsed = time.monotonic() - start
        return self._build_result(all_findings, len(parsed_files), total_lines, elapsed, errors)

    def _build_result(
        self,
        findings: list[Finding],
        files_scanned: int,
        total_lines: int,
        elapsed: float,
        errors: list[dict],
    ) -> ScanResult:
        summary = compute_summary(findings, files_scanned)
        return ScanResult(
            project_path=str(self.config.project_path),
            scanner_version="1.0.0",
            timestamp=datetime.now().isoformat(),
            scan_duration_seconds=round(elapsed, 2),
            files_scanned=files_scanned,
            total_lines=total_lines,
            findings=findings,
            summary=summary,
            errors=errors,
        )


def main(project_path, vuln_types=None, output_format="terminal", output_path=None,
         exclude_patterns=None, severity_min="info", no_color=False, config_path=None):
    """Point d'entree simplifie pour usage direct."""
    from config.schema import ScanConfig

    rules = load_rules(config_path or "config/rules.yaml")
    if vuln_types:
        rules = rules.filter_by_types(vuln_types)

    config = ScanConfig(
        project_path=Path(project_path),
        vuln_types=vuln_types or rules.get_vuln_types(),
        rules=rules,
        severity_min=severity_min,
        exclude_patterns=exclude_patterns or [],
        output_path=Path(output_path) if output_path else None,
        output_format=output_format,
        no_color=no_color,
    )

    scanner = Scanner(config)
    result = scanner.run()

    # Reporter
    from report import generate_report
    generate_report(result, output_format, output_path)

    return result
