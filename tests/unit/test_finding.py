# tests/unit/test_finding.py - Unit tests for Finding, ScanSummary, compute_summary

import pytest
import re

from config.schema import Severity, Confidence
from report.finding import Finding, ScanSummary, compute_summary


class TestFindingFingerprint:
    """Tests for fingerprint generation on Finding instances."""

    def test_fingerprint_generated(self):
        """Creating a Finding should auto-generate a non-empty hex fingerprint."""
        f = Finding(
            vuln_type="sql_injection",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe="CWE-89",
            owasp="A03:2021",
            title="SQL Injection in mysqli_query()",
            description="User input reaches SQL query",
            file_path="/app/test.php",
            line=10,
        )
        assert f.fingerprint, "Fingerprint should not be empty"
        assert len(f.fingerprint) == 16, (
            f"Fingerprint should be 16 hex chars, got {len(f.fingerprint)}"
        )
        assert re.fullmatch(r"[0-9a-f]{16}", f.fingerprint), (
            f"Fingerprint should be lowercase hex, got {f.fingerprint!r}"
        )

    def test_fingerprint_deterministic(self):
        """Two findings with identical key fields should produce the same fingerprint."""
        kwargs = dict(
            vuln_type="xss",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-79",
            owasp="A03:2021",
            title="XSS in echo",
            description="Reflected XSS",
            file_path="/app/page.php",
            line=42,
            sink_function="echo",
            source_variable="$_GET['name']",
        )
        f1 = Finding(**kwargs)
        f2 = Finding(**kwargs)
        assert f1.fingerprint == f2.fingerprint, (
            f"Deterministic: {f1.fingerprint} != {f2.fingerprint}"
        )

    def test_fingerprint_different(self):
        """Two findings with different key fields should produce different fingerprints."""
        common = dict(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-79",
            owasp="A03:2021",
            title="XSS",
            description="XSS",
        )
        f1 = Finding(
            vuln_type="xss",
            file_path="/app/a.php",
            line=10,
            sink_function="echo",
            source_variable="$_GET['x']",
            **common,
        )
        f2 = Finding(
            vuln_type="xss",
            file_path="/app/b.php",
            line=20,
            sink_function="print",
            source_variable="$_POST['y']",
            **common,
        )
        assert f1.fingerprint != f2.fingerprint, (
            f"Different findings should have different fingerprints: "
            f"{f1.fingerprint} == {f2.fingerprint}"
        )

    def test_fingerprint_differs_by_vuln_type(self):
        """Changing only vuln_type should alter the fingerprint."""
        common = dict(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-89",
            owasp="A03:2021",
            title="Injection",
            description="Injection",
            file_path="/app/test.php",
            line=5,
            sink_function="query",
            source_variable="$_GET['id']",
        )
        f1 = Finding(vuln_type="sql_injection", **common)
        f2 = Finding(vuln_type="xss", **common)
        assert f1.fingerprint != f2.fingerprint


class TestComputeSummary:
    """Tests for compute_summary aggregation."""

    def test_compute_summary(self):
        """compute_summary should correctly tally findings by severity and type."""
        findings = [
            Finding(
                vuln_type="sql_injection",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                cwe="CWE-89",
                owasp="A03:2021",
                title="SQLi",
                description="SQLi",
                file_path="/app/a.php",
                line=1,
            ),
            Finding(
                vuln_type="xss",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                cwe="CWE-79",
                owasp="A03:2021",
                title="XSS",
                description="XSS",
                file_path="/app/a.php",
                line=5,
            ),
            Finding(
                vuln_type="sql_injection",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                cwe="CWE-89",
                owasp="A03:2021",
                title="SQLi 2",
                description="SQLi 2",
                file_path="/app/b.php",
                line=10,
            ),
        ]
        summary = compute_summary(findings, files_scanned=5)

        assert summary.total_findings == 3
        assert summary.by_severity.get("critical", 0) == 2
        assert summary.by_severity.get("high", 0) == 1
        assert summary.by_vuln_type.get("sql_injection", 0) == 2
        assert summary.by_vuln_type.get("xss", 0) == 1
        assert summary.by_confidence.get("high", 0) == 2
        assert summary.by_confidence.get("medium", 0) == 1
        assert summary.files_with_findings == 2
        assert summary.files_clean == 3  # 5 scanned - 2 with findings
        assert summary.risk_score > 0.0

    def test_compute_summary_empty(self):
        """compute_summary with empty findings should return zeroed summary."""
        summary = compute_summary([], files_scanned=10)

        assert summary.total_findings == 0
        assert summary.by_severity == {}
        assert summary.by_vuln_type == {}
        assert summary.by_confidence == {}
        assert summary.risk_score == 0.0
        assert summary.files_with_findings == 0
        assert summary.files_clean == 10

    def test_compute_summary_single_file(self):
        """Ensure files_with_findings counts unique file paths."""
        findings = [
            Finding(
                vuln_type="rce",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                cwe="CWE-78",
                owasp="A03:2021",
                title="RCE",
                description="RCE",
                file_path="/app/same.php",
                line=i,
            )
            for i in range(1, 4)
        ]
        summary = compute_summary(findings, files_scanned=1)
        assert summary.files_with_findings == 1
        assert summary.files_clean == 0
