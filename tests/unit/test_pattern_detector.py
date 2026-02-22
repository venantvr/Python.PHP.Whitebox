# tests/unit/test_pattern_detector.py - Unit tests for the regex-based pattern detector

import pytest


class TestPatternDetector:
    """Tests for pattern-based detection (secrets, crypto, configs)."""

    def test_hardcoded_secrets_detected(self, rules, samples_dir):
        """PatternDetector should flag hardcoded passwords, API keys, and tokens."""
        from parser.php_parser import parse_php_file
        from analysis.pattern_detector import PatternDetector

        filepath = str(samples_dir / "scripts" / "hardcoded_secrets.php")
        _, source = parse_php_file(filepath)

        detector = PatternDetector(rules)
        findings = detector.scan_file(filepath, source)

        secret_findings = [
            f for f in findings if f.vuln_type == "hardcoded_secrets"
        ]
        assert len(secret_findings) >= 2, (
            f"Expected at least 2 hardcoded_secrets findings, got {len(secret_findings)}. "
            f"All findings: {[(f.vuln_type, f.title, f.line) for f in findings]}"
        )

    def test_crypto_weakness_detected(self, rules, samples_dir):
        """PatternDetector should flag weak crypto usage (md5, sha1, rand)."""
        from parser.php_parser import parse_php_file
        from analysis.pattern_detector import PatternDetector

        filepath = str(samples_dir / "scripts" / "crypto_weakness.php")
        _, source = parse_php_file(filepath)

        detector = PatternDetector(rules)
        findings = detector.scan_file(filepath, source)

        crypto_findings = [
            f for f in findings if f.vuln_type == "crypto_weakness"
        ]
        assert len(crypto_findings) >= 1, (
            f"Expected at least 1 crypto_weakness finding, got {len(crypto_findings)}. "
            f"All findings: {[(f.vuln_type, f.title, f.line) for f in findings]}"
        )

    def test_clean_file_no_patterns(self, rules, samples_dir):
        """A clean PHP file should produce zero pattern-based findings."""
        from parser.php_parser import parse_php_file
        from analysis.pattern_detector import PatternDetector

        filepath = str(samples_dir / "scripts" / "false_positive_clean.php")
        _, source = parse_php_file(filepath)

        detector = PatternDetector(rules)
        findings = detector.scan_file(filepath, source)

        assert len(findings) == 0, (
            f"Expected 0 findings for a clean file, got {len(findings)}. "
            f"Findings: {[(f.vuln_type, f.title, f.line) for f in findings]}"
        )

    def test_pattern_findings_have_detection_mode(self, rules, samples_dir):
        """All pattern findings should have detection_mode set to 'pattern'."""
        from parser.php_parser import parse_php_file
        from analysis.pattern_detector import PatternDetector

        filepath = str(samples_dir / "scripts" / "hardcoded_secrets.php")
        _, source = parse_php_file(filepath)

        detector = PatternDetector(rules)
        findings = detector.scan_file(filepath, source)

        for f in findings:
            assert f.detection_mode == "pattern", (
                f"Finding at line {f.line} has detection_mode={f.detection_mode!r}, "
                f"expected 'pattern'"
            )

    def test_pattern_findings_have_line_numbers(self, rules, samples_dir):
        """Pattern findings should have valid line numbers (> 0)."""
        from parser.php_parser import parse_php_file
        from analysis.pattern_detector import PatternDetector

        filepath = str(samples_dir / "scripts" / "hardcoded_secrets.php")
        _, source = parse_php_file(filepath)

        detector = PatternDetector(rules)
        findings = detector.scan_file(filepath, source)

        for f in findings:
            assert f.line > 0, (
                f"Finding should have line > 0, got {f.line}"
            )
