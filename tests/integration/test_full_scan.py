# tests/integration/test_full_scan.py - Integration tests for the full Scanner pipeline

import json
import os
import shutil
import pytest
from pathlib import Path

from report.finding import ScanResult


class TestFullScanPipeline:
    """Integration tests running the complete Scanner pipeline."""

    def test_full_scan_samples_dir(self, full_scan, samples_dir):
        """Running Scanner on the samples directory should produce a ScanResult with findings."""
        result = full_scan(samples_dir)
        assert isinstance(result, ScanResult)
        assert result.files_scanned > 0, "Scanner should have scanned at least 1 file"
        assert len(result.findings) > 0, (
            f"Scanner should find vulnerabilities in test samples, "
            f"scanned {result.files_scanned} files"
        )
        assert result.summary is not None
        assert result.summary.total_findings == len(result.findings)

    def test_full_scan_json_output(self, full_scan, samples_dir, tmp_path):
        """Generating a JSON report should produce a valid JSON file."""
        from report import generate_report

        result = full_scan(samples_dir)
        output_path = str(tmp_path / "report.json")
        generated_path = generate_report(result, "json", output_path)

        assert os.path.exists(generated_path), (
            f"JSON report should exist at {generated_path}"
        )

        with open(generated_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        # Verify SARIF structure
        assert "version" in data, "JSON report should contain SARIF version"
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) >= 1
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert run["tool"]["driver"]["name"] == "Python.PHP.Whitebox"

    def test_full_scan_mixed_vulns(self, full_scan, samples_dir, tmp_path):
        """Scanning a directory with mixed vulnerability types should detect multiple categories."""
        # Copy relevant sample files into a temp directory to isolate the test
        mixed_dir = tmp_path / "mixed"
        mixed_dir.mkdir()

        # Copy files if they exist; skip gracefully if absent
        sample_files = [
            "scripts/sqli_direct.php",
            "scripts/xss_direct.php",
            "scripts/rce_direct.php",
            "scripts/hardcoded_secrets.php",
        ]
        copied = 0
        for name in sample_files:
            src = samples_dir / name
            if src.exists():
                shutil.copy2(str(src), str(mixed_dir / Path(name).name))
                copied += 1

        if copied == 0:
            pytest.skip("No sample files available to copy for mixed vuln test")

        result = full_scan(str(mixed_dir))

        vuln_types_found = {f.vuln_type for f in result.findings}
        # We expect at least 2 different vulnerability types from the mixed samples
        assert len(vuln_types_found) >= 2, (
            f"Expected at least 2 distinct vuln types, got {vuln_types_found}"
        )

    def test_full_scan_clean_file(self, rules, samples_dir):
        """Scanning a known-clean file should produce minimal or zero findings."""
        from config.schema import ScanConfig
        from scanner import Scanner

        clean_file = samples_dir / "scripts/false_positive_clean.php"
        if not clean_file.exists():
            pytest.skip("false_positive_clean.php not yet created")

        # Scan only the directory containing the clean file
        # We use the full samples dir but we will filter results to only this file
        config = ScanConfig(
            project_path=samples_dir,
            vuln_types=rules.get_vuln_types(),
            rules=rules,
            severity_min="info",
            exclude_patterns=[],
            output_format="terminal",
            no_color=True,
            show_progress=False,
        )
        scanner = Scanner(config)
        result = scanner.run()

        # Filter to only findings from the clean file
        clean_path = str(clean_file)
        clean_findings = [f for f in result.findings if f.file_path == clean_path]

        assert len(clean_findings) == 0, (
            f"Clean file should produce 0 findings, got {len(clean_findings)}. "
            f"Findings: {[(f.vuln_type, f.title, f.line) for f in clean_findings]}"
        )

    def test_full_scan_result_structure(self, full_scan, samples_dir):
        """ScanResult should have all expected fields populated."""
        result = full_scan(samples_dir)

        assert result.scanner_version, "scanner_version should be set"
        assert result.timestamp, "timestamp should be set"
        assert result.scan_duration_seconds >= 0, "scan duration should be non-negative"
        assert result.project_path, "project_path should be set"
        assert isinstance(result.findings, list)
        assert isinstance(result.errors, list)

    def test_full_scan_summary_consistency(self, full_scan, samples_dir):
        """ScanSummary totals should match actual finding counts."""
        result = full_scan(samples_dir)

        if not result.findings:
            pytest.skip("No findings to verify summary against")

        summary = result.summary
        assert summary is not None

        # Total findings should match
        assert summary.total_findings == len(result.findings)

        # Sum of severity counts should match total
        severity_sum = sum(summary.by_severity.values())
        assert severity_sum == summary.total_findings, (
            f"by_severity sum ({severity_sum}) != total ({summary.total_findings})"
        )

        # Sum of vuln_type counts should match total
        vuln_type_sum = sum(summary.by_vuln_type.values())
        assert vuln_type_sum == summary.total_findings, (
            f"by_vuln_type sum ({vuln_type_sum}) != total ({summary.total_findings})"
        )

        # files_with_findings + files_clean should equal files_scanned
        assert summary.files_with_findings + summary.files_clean == result.files_scanned


class TestFullScanEdgeCases:
    """Edge case tests for the Scanner pipeline."""

    def test_scan_empty_directory(self, full_scan, tmp_path):
        """Scanning an empty directory should return zero findings without error."""
        result = full_scan(str(tmp_path))
        assert isinstance(result, ScanResult)
        assert result.files_scanned == 0
        assert len(result.findings) == 0

    def test_scan_with_exclude_patterns(self, full_scan, samples_dir, tmp_path):
        """Exclude patterns should prevent certain files from being scanned."""
        # Set up a directory structure
        included_dir = tmp_path / "src"
        excluded_dir = tmp_path / "excluded"
        included_dir.mkdir()
        excluded_dir.mkdir()

        (included_dir / "app.php").write_text(
            '<?php $x = $_GET["id"]; echo $x; ?>'
        )
        (excluded_dir / "test.php").write_text(
            '<?php $x = $_GET["id"]; echo $x; ?>'
        )

        result = full_scan(str(tmp_path), exclude=["excluded/*"])

        # Should have scanned at least the included file
        finding_files = {f.file_path for f in result.findings}
        excluded_paths = [p for p in finding_files if "excluded" in p]
        assert len(excluded_paths) == 0, (
            f"Excluded directory files should not appear in findings: {excluded_paths}"
        )
