# tests/unit/test_rules.py - Unit tests for the rules configuration loader

import pytest

from config.loader import RulesConfig


class TestLoadRules:
    """Tests for loading and querying the rules configuration."""

    def test_load_rules(self, rules):
        """The loaded rules should contain all expected top-level sections."""
        assert isinstance(rules, RulesConfig)
        assert len(rules.sources) > 0, "Should have superglobal sources"
        assert len(rules.filters) > 0, "Should have filters"
        assert len(rules.propagators) > 0, "Should have propagators"
        assert len(rules.vulnerabilities) > 0, "Should have vulnerability definitions"

    def test_is_source_get(self, rules):
        """$_GET should be recognized as a taint source."""
        assert rules.is_source("$_GET"), "$_GET should be a source"

    def test_is_source_post(self, rules):
        """$_POST should be recognized as a taint source."""
        assert rules.is_source("$_POST"), "$_POST should be a source"

    def test_is_source_cookie(self, rules):
        """$_COOKIE should be recognized as a taint source."""
        assert rules.is_source("$_COOKIE"), "$_COOKIE should be a source"

    def test_is_source_request(self, rules):
        """$_REQUEST should be recognized as a taint source."""
        assert rules.is_source("$_REQUEST"), "$_REQUEST should be a source"

    def test_is_source_server(self, rules):
        """$_SERVER should be recognized as a taint source."""
        assert rules.is_source("$_SERVER"), "$_SERVER should be a source"

    def test_is_not_source(self, rules):
        """A regular variable should not be a source."""
        assert not rules.is_source("$myvar"), "$myvar should NOT be a source"

    def test_get_sink_vuln_mysqli_query(self, rules):
        """mysqli_query should be mapped to the sql_injection vulnerability."""
        vuln = rules.get_sink_vuln("mysqli_query")
        assert vuln is not None, "mysqli_query should be a known sink"
        assert vuln.vuln_type == "sql_injection"
        assert vuln.cwe == "CWE-89"

    def test_get_sink_vuln_system(self, rules):
        """system() should be mapped to the rce vulnerability."""
        vuln = rules.get_sink_vuln("system")
        assert vuln is not None, "system should be a known sink"
        assert vuln.vuln_type == "rce"

    def test_get_sink_vuln_unknown(self, rules):
        """An unknown function should return None from get_sink_vuln."""
        vuln = rules.get_sink_vuln("my_custom_function")
        assert vuln is None

    def test_get_filter_info_htmlspecialchars(self, rules):
        """htmlspecialchars should neutralize xss."""
        info = rules.get_filter_info("htmlspecialchars")
        assert info is not None, "htmlspecialchars should be a known filter"
        assert "xss" in info.neutralizes, (
            f"htmlspecialchars should neutralize xss, neutralizes: {info.neutralizes}"
        )

    def test_get_filter_info_escapeshellarg(self, rules):
        """escapeshellarg should neutralize rce."""
        info = rules.get_filter_info("escapeshellarg")
        assert info is not None, "escapeshellarg should be a known filter"
        assert "rce" in info.neutralizes

    def test_get_filter_info_intval(self, rules):
        """intval should neutralize multiple vulnerability types."""
        info = rules.get_filter_info("intval")
        assert info is not None, "intval should be a known filter"
        assert "sql_injection" in info.neutralizes
        assert "xss" in info.neutralizes

    def test_get_filter_info_unknown(self, rules):
        """An unknown function should return None from get_filter_info."""
        info = rules.get_filter_info("totally_made_up")
        assert info is None

    def test_is_propagator_trim(self, rules):
        """trim should be recognized as a propagator."""
        assert rules.is_propagator("trim"), "trim should be a propagator"

    def test_is_propagator_strtolower(self, rules):
        """strtolower should be recognized as a propagator."""
        assert rules.is_propagator("strtolower"), "strtolower should be a propagator"

    def test_is_propagator_substr(self, rules):
        """substr should be recognized as a propagator."""
        assert rules.is_propagator("substr"), "substr should be a propagator"

    def test_is_not_propagator(self, rules):
        """A non-propagator function should return False."""
        assert not rules.is_propagator("htmlspecialchars"), (
            "htmlspecialchars is a filter, not a propagator"
        )

    def test_get_vuln_types(self, rules):
        """get_vuln_types should return all configured vulnerability type names."""
        vuln_types = rules.get_vuln_types()
        assert "sql_injection" in vuln_types
        assert "xss" in vuln_types
        assert "rce" in vuln_types
        assert "file_inclusion" in vuln_types

    def test_vulnerability_has_cwe(self, rules):
        """Every vulnerability rule should have a CWE identifier."""
        for vuln_type, rule in rules.vulnerabilities.items():
            assert rule.cwe, f"{vuln_type} should have a CWE identifier"

    def test_filter_by_types(self, rules):
        """filter_by_types should return a RulesConfig with only the specified types."""
        filtered = rules.filter_by_types(["sql_injection", "xss"])
        assert "sql_injection" in filtered.vulnerabilities
        assert "xss" in filtered.vulnerabilities
        assert "rce" not in filtered.vulnerabilities
