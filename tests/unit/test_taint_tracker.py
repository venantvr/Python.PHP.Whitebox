# tests/unit/test_taint_tracker.py - Unit tests for the taint tracker engine

import pytest


class TestSQLInjection:
    """Tests for SQL injection detection via taint tracking."""

    def test_sqli_direct_detected(self, scan_file):
        """Direct user input flowing to mysqli_query should be flagged."""
        findings = scan_file("scripts/sqli_direct.php")
        sqli_findings = [f for f in findings if f.vuln_type == "sql_injection"]
        assert len(sqli_findings) >= 1, (
            f"Expected at least 1 sql_injection finding, got {len(sqli_findings)}. "
            f"All findings: {[f.vuln_type for f in findings]}"
        )

    def test_sqli_sanitized_no_findings(self, scan_file):
        """Properly sanitized SQL input should produce no sql_injection findings."""
        findings = scan_file("scripts/sqli_sanitized.php")
        sqli_findings = [f for f in findings if f.vuln_type == "sql_injection"]
        assert len(sqli_findings) == 0, (
            f"Expected 0 sql_injection findings for sanitized code, got {len(sqli_findings)}. "
            f"Findings: {[(f.title, f.line) for f in sqli_findings]}"
        )

    def test_sqli_multistep_detected(self, scan_file):
        """Taint should propagate through trim/strtolower to detect multi-step SQLi."""
        findings = scan_file("scripts/sqli_multistep.php")
        sqli_findings = [f for f in findings if f.vuln_type == "sql_injection"]
        assert len(sqli_findings) >= 1, (
            f"Expected at least 1 sql_injection finding through propagators, "
            f"got {len(sqli_findings)}. All findings: {[f.vuln_type for f in findings]}"
        )


class TestXSS:
    """Tests for Cross-Site Scripting detection via taint tracking."""

    def test_xss_direct_detected(self, scan_file):
        """Direct echo of user input should be flagged as XSS."""
        findings = scan_file("scripts/xss_direct.php")
        xss_findings = [f for f in findings if f.vuln_type == "xss"]
        assert len(xss_findings) >= 1, (
            f"Expected at least 1 xss finding, got {len(xss_findings)}. "
            f"All findings: {[f.vuln_type for f in findings]}"
        )

    def test_xss_sanitized_no_findings(self, scan_file):
        """htmlspecialchars-sanitized output should not produce xss findings."""
        findings = scan_file("scripts/xss_sanitized.php")
        xss_findings = [f for f in findings if f.vuln_type == "xss"]
        assert len(xss_findings) == 0, (
            f"Expected 0 xss findings for sanitized code, got {len(xss_findings)}. "
            f"Findings: {[(f.title, f.line) for f in xss_findings]}"
        )

    def test_xss_concatenation_detected(self, scan_file):
        """Tainted variable concatenated into echo output should be flagged."""
        findings = scan_file("scripts/xss_concatenation.php")
        xss_findings = [f for f in findings if f.vuln_type == "xss"]
        assert len(xss_findings) >= 1, (
            f"Expected at least 1 xss finding via concatenation, "
            f"got {len(xss_findings)}. All findings: {[f.vuln_type for f in findings]}"
        )


class TestRCE:
    """Tests for Remote Code Execution detection via taint tracking."""

    def test_rce_direct_detected(self, scan_file):
        """Direct user input to system/exec should be flagged as RCE."""
        findings = scan_file("scripts/rce_direct.php")
        rce_findings = [f for f in findings if f.vuln_type == "rce"]
        assert len(rce_findings) >= 1, (
            f"Expected at least 1 rce finding, got {len(rce_findings)}. "
            f"All findings: {[f.vuln_type for f in findings]}"
        )

    def test_rce_sanitized_no_findings(self, scan_file):
        """escapeshellarg-sanitized input should not produce rce findings."""
        findings = scan_file("scripts/rce_sanitized.php")
        rce_findings = [f for f in findings if f.vuln_type == "rce"]
        assert len(rce_findings) == 0, (
            f"Expected 0 rce findings for sanitized code, got {len(rce_findings)}. "
            f"Findings: {[(f.title, f.line) for f in rce_findings]}"
        )


class TestFileInclusion:
    """Tests for Local/Remote File Inclusion detection."""

    def test_file_inclusion_detected(self, scan_file):
        """User input in include/require should be flagged as file_inclusion."""
        findings = scan_file("scripts/file_inclusion.php")
        fi_findings = [f for f in findings if f.vuln_type == "file_inclusion"]
        assert len(fi_findings) >= 1, (
            f"Expected at least 1 file_inclusion finding, got {len(fi_findings)}. "
            f"All findings: {[f.vuln_type for f in findings]}"
        )


class TestPathTraversal:
    """Tests for path traversal detection."""

    def test_path_traversal_detected(self, scan_file):
        """User input in file operations should be flagged as path_traversal."""
        findings = scan_file("scripts/path_traversal.php")
        pt_findings = [f for f in findings if f.vuln_type == "path_traversal"]
        assert len(pt_findings) >= 1, (
            f"Expected at least 1 path_traversal finding, got {len(pt_findings)}. "
            f"All findings: {[f.vuln_type for f in findings]}"
        )


class TestSSRF:
    """Tests for Server-Side Request Forgery detection."""

    def test_ssrf_detected(self, scan_file):
        """User input in curl/file_get_contents URL should be flagged as SSRF."""
        findings = scan_file("scripts/ssrf.php")
        ssrf_findings = [f for f in findings if f.vuln_type == "ssrf"]
        assert len(ssrf_findings) >= 1, (
            f"Expected at least 1 ssrf finding, got {len(ssrf_findings)}. "
            f"All findings: {[f.vuln_type for f in findings]}"
        )


class TestOpenRedirect:
    """Tests for open redirect detection."""

    def test_open_redirect_detected(self, scan_file):
        """User input in header('Location: ...') should be flagged as open_redirect."""
        findings = scan_file("scripts/open_redirect.php")
        or_findings = [f for f in findings if f.vuln_type == "open_redirect"]
        assert len(or_findings) >= 1, (
            f"Expected at least 1 open_redirect finding, got {len(or_findings)}. "
            f"All findings: {[f.vuln_type for f in findings]}"
        )


class TestInsecureDeserialization:
    """Tests for insecure deserialization detection."""

    def test_insecure_deserialization_detected(self, scan_file):
        """User input passed to unserialize() should be flagged."""
        findings = scan_file("scripts/insecure_deserialization.php")
        deser_findings = [
            f for f in findings
            if f.vuln_type == "insecure_deserialization"
        ]
        assert len(deser_findings) >= 1, (
            f"Expected at least 1 insecure_deserialization finding, "
            f"got {len(deser_findings)}. All findings: {[f.vuln_type for f in findings]}"
        )


class TestConditionalTaint:
    """Tests for taint propagation through conditional branches."""

    def test_conditional_taint(self, scan_file):
        """Taint should propagate through if/else branches conservatively."""
        findings = scan_file("scripts/conditional_taint.php")
        assert len(findings) >= 1, (
            f"Expected at least 1 finding from conditional taint propagation, "
            f"got {len(findings)}"
        )


class TestFindingMetadata:
    """Tests verifying metadata on findings from taint tracking."""

    def test_sqli_finding_has_data_flow(self, scan_file):
        """SQL injection findings should include a non-empty data flow trace."""
        findings = scan_file("scripts/sqli_direct.php")
        sqli_findings = [f for f in findings if f.vuln_type == "sql_injection"]
        assert len(sqli_findings) >= 1
        for f in sqli_findings:
            assert len(f.data_flow) >= 1, (
                f"Finding at line {f.line} should have data_flow steps"
            )

    def test_sqli_finding_has_source_variable(self, scan_file):
        """SQL injection findings should identify the source variable."""
        findings = scan_file("scripts/sqli_direct.php")
        sqli_findings = [f for f in findings if f.vuln_type == "sql_injection"]
        assert len(sqli_findings) >= 1
        for f in sqli_findings:
            assert f.source_variable, (
                f"Finding at line {f.line} should have a source_variable set"
            )

    def test_finding_has_cwe_and_owasp(self, scan_file):
        """All taint findings should carry CWE and OWASP identifiers."""
        findings = scan_file("scripts/sqli_direct.php")
        sqli_findings = [f for f in findings if f.vuln_type == "sql_injection"]
        assert len(sqli_findings) >= 1
        for f in sqli_findings:
            assert f.cwe.startswith("CWE-"), f"Expected CWE id, got {f.cwe!r}"
            assert f.owasp, f"Expected OWASP id, got {f.owasp!r}"
