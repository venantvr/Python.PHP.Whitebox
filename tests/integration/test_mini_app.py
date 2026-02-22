# tests/integration/test_mini_app.py - Tests complexes sur la mini-app PHP
#
# These tests verify detection on a realistic PHP application with:
# - Classes, methods, parameter passing
# - Multi-step taint propagation through method chains
# - Mixed safe/unsafe patterns in the same class
# - Complex data flows: ternary, heredoc, augmented assignment, switch

import pytest
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "php_samples" / "app"


class TestUserController:
    """Tests on UserController.php - user CRUD with mixed safe/unsafe methods."""

    def test_detects_open_redirect(self, scan_file_full):
        findings = scan_file_full("app/UserController.php")
        redirects = [f for f in findings if f.vuln_type == "open_redirect"]
        assert len(redirects) >= 1, (
            f"Expected open_redirect from logout(), got {len(redirects)}. "
            f"All: {[f.vuln_type for f in findings]}"
        )

    def test_open_redirect_traces_to_get_param(self, scan_file_full):
        """Data flow should trace from $_GET['redirect_url'] to header()."""
        findings = scan_file_full("app/UserController.php")
        redirects = [f for f in findings if f.vuln_type == "open_redirect"]
        assert len(redirects) >= 1
        f = redirects[0]
        assert f.source_variable and "redirect_url" in f.source_variable
        assert f.sink_function == "header"

    def test_no_sqli_from_safe_method(self, scan_file_full):
        """getUserSafe() uses intval - should NOT produce sql_injection."""
        findings = scan_file_full("app/UserController.php")
        sqli = [f for f in findings if f.vuln_type == "sql_injection"]
        # getUserSafe uses intval() so should not trigger
        for f in sqli:
            assert "getUserSafe" not in (f.code_snippet or ""), (
                f"getUserSafe should not trigger SQLi: {f.code_snippet}"
            )


class TestAuthService:
    """Tests on AuthService.php - authentication with crypto and secrets."""

    def test_detects_hardcoded_secret(self, scan_file_full):
        findings = scan_file_full("app/AuthService.php")
        secrets = [f for f in findings if f.vuln_type == "hardcoded_secrets"]
        assert len(secrets) >= 1, (
            f"Expected hardcoded_secrets for $secret_key, got {len(secrets)}. "
            f"All: {[f.vuln_type for f in findings]}"
        )

    def test_detects_weak_crypto(self, scan_file_full):
        """md5() used for password hashing should be flagged."""
        findings = scan_file_full("app/AuthService.php")
        crypto = [f for f in findings if f.vuln_type == "crypto_weakness"]
        assert len(crypto) >= 1, (
            f"Expected crypto_weakness for md5(), got {len(crypto)}. "
            f"All: {[f.vuln_type for f in findings]}"
        )

    def test_pattern_findings_have_line_info(self, scan_file_full):
        """All pattern-detected findings should have valid line numbers."""
        findings = scan_file_full("app/AuthService.php")
        for f in findings:
            assert f.line > 0, f"Finding {f.vuln_type} should have line > 0"


class TestFileManager:
    """Tests on FileManager.php - file operations with path traversal, upload, SSRF."""

    def test_detects_path_traversal(self, scan_file_full):
        findings = scan_file_full("app/FileManager.php")
        pt = [f for f in findings if f.vuln_type == "path_traversal"]
        assert len(pt) >= 1, (
            f"Expected path_traversal from downloadFile/deleteFile, got {len(pt)}. "
            f"All: {[f.vuln_type for f in findings]}"
        )

    def test_detects_insecure_upload(self, scan_file_full):
        findings = scan_file_full("app/FileManager.php")
        uploads = [f for f in findings if f.vuln_type == "insecure_upload"]
        assert len(uploads) >= 1, (
            f"Expected insecure_upload from uploadAvatar(), got {len(uploads)}"
        )

    def test_detects_xss_in_listing(self, scan_file_full):
        """listFiles() echoes $_GET['filter'] without encoding."""
        findings = scan_file_full("app/FileManager.php")
        xss = [f for f in findings if f.vuln_type == "xss"]
        assert len(xss) >= 1, (
            f"Expected xss from listFiles(), got {len(xss)}"
        )

    def test_safe_download_not_flagged(self, scan_file_full):
        """downloadFileSafe uses basename() - should not produce path_traversal at that line."""
        findings = scan_file_full("app/FileManager.php")
        pt = [f for f in findings if f.vuln_type == "path_traversal"]
        for f in pt:
            # The safe method is around lines 30-37
            assert "basename" not in (f.code_snippet or ""), (
                f"basename-sanitized path should not trigger: {f.code_snippet}"
            )

    def test_multiple_vuln_types_in_one_file(self, scan_file_full):
        """FileManager should have at least 3 different vuln categories."""
        findings = scan_file_full("app/FileManager.php")
        vuln_types = {f.vuln_type for f in findings}
        assert len(vuln_types) >= 3, (
            f"Expected >= 3 vuln types, got {vuln_types}"
        )


class TestApiHandler:
    """Tests on ApiHandler.php - REST API with multiple vulnerability types."""

    def test_detects_findings(self, scan_file_full):
        """ApiHandler should produce at least 1 finding."""
        findings = scan_file_full("app/ApiHandler.php")
        assert len(findings) >= 1, (
            f"Expected findings from ApiHandler, got {len(findings)}"
        )

    def test_findings_have_data_flow(self, scan_file_full):
        """Taint findings should include data flow traces."""
        findings = scan_file_full("app/ApiHandler.php")
        taint_findings = [f for f in findings if f.detection_mode == "taint"]
        for f in taint_findings:
            assert len(f.data_flow) >= 2, (
                f"Finding {f.vuln_type} at line {f.line} should have >= 2 data flow steps, "
                f"got {len(f.data_flow)}"
            )


class TestDataProcessor:
    """Tests on DataProcessor.php - complex data flows."""

    def test_detects_xss_via_ternary(self, scan_file_full):
        """displayMessage() uses ternary with $_GET - should detect XSS."""
        findings = scan_file_full("app/DataProcessor.php")
        xss = [f for f in findings if f.vuln_type == "xss"]
        assert len(xss) >= 1, (
            f"Expected xss from ternary expression, got {len(xss)}. "
            f"All: {[f.vuln_type for f in findings]}"
        )

    def test_detects_xss_via_augmented_assignment(self, scan_file_full):
        """buildReport() uses $html .= tainted - should detect XSS."""
        findings = scan_file_full("app/DataProcessor.php")
        xss = [f for f in findings if f.vuln_type == "xss"]
        # Should have at least 2 XSS: ternary + augmented assignment
        assert len(xss) >= 2, (
            f"Expected >= 2 xss findings (ternary + augmented), got {len(xss)}"
        )

    def test_detects_session_fixation(self, scan_file_full):
        """setSessionFromInput() passes $_GET to session_id()."""
        findings = scan_file_full("app/DataProcessor.php")
        sf = [f for f in findings if f.vuln_type == "session_fixation"]
        assert len(sf) >= 1, (
            f"Expected session_fixation, got {len(sf)}. "
            f"All: {[f.vuln_type for f in findings]}"
        )

    def test_session_fixation_traces_to_get(self, scan_file_full):
        """Data flow should show $_GET['session_id'] -> session_id()."""
        findings = scan_file_full("app/DataProcessor.php")
        sf = [f for f in findings if f.vuln_type == "session_fixation"]
        assert len(sf) >= 1
        f = sf[0]
        assert f.sink_function == "session_id"
        assert f.source_variable and "session_id" in f.source_variable


class TestSecureApp:
    """Tests on SecureApp.php - all properly sanitized, ZERO findings expected."""

    def test_zero_findings(self, scan_file_full):
        """SecureApp uses intval, htmlspecialchars, escapeshellarg, basename, prepared stmts."""
        findings = scan_file_full("app/SecureApp.php")
        assert len(findings) == 0, (
            f"SecureApp should produce 0 findings, got {len(findings)}: "
            f"{[(f.vuln_type, f.line, f.code_snippet) for f in findings]}"
        )


class TestMiniAppFullPipeline:
    """Integration tests running the full Scanner pipeline on the mini-app directory."""

    def test_full_scan_detects_multiple_vuln_types(self, full_scan):
        result = full_scan(str(APP_DIR))
        vuln_types = {f.vuln_type for f in result.findings}
        # We expect at least 5 distinct types across the app
        assert len(vuln_types) >= 5, (
            f"Expected >= 5 vuln types across mini-app, got {vuln_types}"
        )

    def test_full_scan_finding_count(self, full_scan):
        result = full_scan(str(APP_DIR))
        assert len(result.findings) >= 12, (
            f"Expected >= 12 findings across mini-app, got {len(result.findings)}"
        )

    def test_full_scan_files_scanned(self, full_scan):
        result = full_scan(str(APP_DIR))
        assert result.files_scanned == 6, (
            f"Expected 6 PHP files scanned, got {result.files_scanned}"
        )

    def test_secure_app_is_clean(self, full_scan):
        """SecureApp.php should not contribute any findings in full scan."""
        result = full_scan(str(APP_DIR))
        secure_path = str(APP_DIR / "SecureApp.php")
        secure_findings = [f for f in result.findings if f.file_path == secure_path]
        assert len(secure_findings) == 0, (
            f"SecureApp.php should have 0 findings, got: "
            f"{[(f.vuln_type, f.line) for f in secure_findings]}"
        )

    def test_summary_consistency(self, full_scan):
        result = full_scan(str(APP_DIR))
        summary = result.summary
        assert summary.total_findings == len(result.findings)
        assert sum(summary.by_severity.values()) == summary.total_findings
        assert sum(summary.by_vuln_type.values()) == summary.total_findings

    def test_json_report_generation(self, full_scan, tmp_path):
        """JSON/SARIF report should include findings from the mini-app."""
        from report import generate_report

        result = full_scan(str(APP_DIR))
        output = str(tmp_path / "app_report.json")
        generate_report(result, "json", output)

        import json
        with open(output) as fh:
            data = json.load(fh)

        assert data["version"] == "2.1.0"
        run = data["runs"][0]
        assert len(run["results"]) == len(result.findings)
        # Verify codeFlows exist for taint findings
        taint_results = [r for r in run["results"] if r.get("codeFlows")]
        assert len(taint_results) >= 1, "Expected at least 1 SARIF result with codeFlows"

    def test_html_report_generation(self, full_scan, tmp_path):
        """HTML report should be generated without error."""
        from report import generate_report

        result = full_scan(str(APP_DIR))
        output = str(tmp_path / "app_report.html")
        generate_report(result, "html", output)

        with open(output) as fh:
            html = fh.read()

        assert "<html" in html
        assert "Python.PHP.Whitebox" in html
        assert "xss" in html.lower() or "XSS" in html
