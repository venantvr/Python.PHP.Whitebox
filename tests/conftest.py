# tests/conftest.py - Shared fixtures for Python.PHP.Whitebox tests

import os
import sys
import pytest
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SAMPLES_DIR = PROJECT_ROOT / "tests" / "php_samples"


@pytest.fixture
def rules():
    """Load the default rules configuration."""
    from config.loader import load_rules
    return load_rules(str(PROJECT_ROOT / "config" / "rules.yaml"))


@pytest.fixture
def samples_dir():
    """Path to PHP sample files."""
    return SAMPLES_DIR


@pytest.fixture
def scan_file(rules):
    """Helper to run taint analysis on a single PHP file.

    Returns list[Finding].
    """
    from parser.php_parser import parse_php_file
    from analysis.taint_tracker import TaintTracker
    from analysis.cross_file_context import CrossFileContext

    def _scan(filename):
        filepath = str(SAMPLES_DIR / filename)
        tree, source = parse_php_file(filepath)
        ctx = CrossFileContext()
        tracker = TaintTracker(
            source_code=source,
            tree=tree,
            file_path=filepath,
            rules=rules,
            global_context=ctx,
        )
        return tracker.analyze()

    return _scan


@pytest.fixture
def scan_file_full(rules):
    """Helper to run full analysis pipeline (taint + patterns + detectors) on a single file.

    Returns list[Finding].
    """
    from parser.php_parser import parse_php_file
    from analysis.taint_tracker import TaintTracker
    from analysis.cross_file_context import CrossFileContext
    from analysis.pattern_detector import PatternDetector
    from analysis.context_analyzer import ContextAnalyzer
    from detectors import get_all_detectors

    def _scan(filename):
        filepath = str(SAMPLES_DIR / filename)
        tree, source = parse_php_file(filepath)
        ctx = CrossFileContext()

        # Taint analysis
        tracker = TaintTracker(
            source_code=source,
            tree=tree,
            file_path=filepath,
            rules=rules,
            global_context=ctx,
        )
        taint_findings = tracker.analyze()

        # Pattern detection
        pattern_detector = PatternDetector(rules)
        pattern_findings = pattern_detector.scan_file(filepath, source)

        # Combine
        all_findings = taint_findings + pattern_findings

        # Context refinement
        analyzer = ContextAnalyzer()
        all_findings = analyzer.refine_findings(all_findings, source)

        # Detectors
        detectors = get_all_detectors(rules)
        refined = []
        for detector in detectors:
            refined.extend(detector.detect(all_findings, filepath, source))

        # Also keep pattern findings not covered by detectors
        pattern_types = {f.vuln_type for f in pattern_findings}
        detector_types = {d.vuln_type for d in detectors}
        for f in all_findings:
            if f.vuln_type in pattern_types and f.vuln_type not in detector_types:
                refined.append(f)

        return refined

    return _scan


@pytest.fixture
def full_scan(rules):
    """Run a full Scanner pipeline on a directory."""
    from config.schema import ScanConfig
    from scanner import Scanner

    def _scan(directory, vuln_types=None, exclude=None):
        config = ScanConfig(
            project_path=Path(directory),
            vuln_types=vuln_types or rules.get_vuln_types(),
            rules=rules,
            severity_min="info",
            exclude_patterns=exclude or [],
            output_format="terminal",
            no_color=True,
            show_progress=False,
        )
        scanner = Scanner(config)
        return scanner.run()

    return _scan
