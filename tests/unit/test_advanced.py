# tests/unit/test_advanced.py - Gardes, inter-procedural, WordPress, frameworks, templates
#
# Chaque test verifie des lignes precises : les lignes "VULN" doivent etre
# signalees, les lignes "SAFE" ne doivent PAS l'etre.

import pytest


def _lines(findings, vuln_type=None):
    return {f.line for f in findings if vuln_type is None or f.vuln_type == vuln_type}


def _by_line(findings, line):
    return [f for f in findings if f.line == line]


class TestGuards:
    """scripts/guards.php - validation dans les conditions."""

    @pytest.fixture(autouse=True)
    def _scan(self, scan_file_full):
        self.findings = scan_file_full("scripts/guards.php")

    def test_early_exit_on_is_numeric_sanitizes(self):
        assert 9 not in _lines(self.findings, "sql_injection")

    def test_in_array_whitelist_sanitizes_then_branch(self):
        assert 15 not in _lines(self.findings, "sql_injection")
        assert 17 not in _lines(self.findings, "sql_injection")

    def test_validation_in_then_does_not_protect_else(self):
        assert 25 in _lines(self.findings, "file_inclusion")

    def test_strict_regex_sanitizes(self):
        assert 33 not in _lines(self.findings, "path_traversal")

    def test_loose_regex_does_not_sanitize(self):
        assert 38 in _lines(self.findings, "path_traversal")

    def test_literal_comparison_sanitizes(self):
        assert 43 not in _lines(self.findings, "rce")

    def test_arithmetic_result_is_clean(self):
        assert 48 not in _lines(self.findings, "sql_injection")

    def test_isset_whitelist_lookup(self):
        assert 54 not in _lines(self.findings, "file_inclusion")
        assert 55 not in _lines(self.findings, "xss")

    def test_filter_var_flag_aware(self):
        assert 60 not in _lines(self.findings, "sql_injection")
        assert 63 in _lines(self.findings, "sql_injection")

    def test_preg_match_strict_capture_is_clean(self):
        assert 67 not in _lines(self.findings, "sql_injection")

    def test_per_label_sanitization(self):
        """htmlspecialchars($a) . $b : $b reste dangereux."""
        f = _by_line(self.findings, 71)
        assert any(x.vuln_type == "xss" and "label" in x.source_variable for x in f), f

    def test_server_keys(self):
        assert 74 not in _lines(self.findings, "xss")
        assert 75 in _lines(self.findings, "xss")

    def test_weak_sanitizer_lowers_confidence(self):
        from config.schema import Confidence
        f = [x for x in _by_line(self.findings, 79) if x.vuln_type == "sql_injection"]
        assert f and f[0].confidence == Confidence.LOW


class TestInterprocedural:
    """scripts/interprocedural.php - parametres -> sinks, retours, proprietes, closures."""

    @pytest.fixture(autouse=True)
    def _scan(self, scan_file_full):
        self.findings = scan_file_full("scripts/interprocedural.php")

    def test_param_reaches_sink_in_callee(self):
        f = [x for x in _by_line(self.findings, 5) if x.vuln_type == "sql_injection"]
        assert f, "sink inside run_query() should be reported via the call site"
        assert f[0].source_variable == "$_GET['x']"
        assert any("Passed as argument" in s.description for s in f[0].data_flow)
        assert f[0].function_name == "run_query"

    def test_return_value_propagates_param_taint(self):
        assert 56 in _lines(self.findings, "sql_injection")

    def test_return_value_of_sanitized_argument_is_clean(self):
        assert 60 not in _lines(self.findings, "sql_injection")

    def test_user_defined_sanitizer_via_preg_replace_whitelist(self):
        assert 64 not in _lines(self.findings, "sql_injection")

    def test_method_call_site_resolution(self):
        assert 30 in _lines(self.findings, "sql_injection")
        assert 35 not in _lines(self.findings, "sql_injection")

    def test_class_property_taint_across_methods(self):
        assert 43 in _lines(self.findings, "sql_injection")

    def test_static_method_call_site(self):
        assert 47 in _lines(self.findings, "xss")

    def test_closure_use_capture(self):
        assert 76 in _lines(self.findings, "rce")

    def test_loop_findings_deduplicated(self):
        assert len([x for x in _by_line(self.findings, 84) if x.vuln_type == "xss"]) == 1

    def test_backticks_are_rce_sink(self):
        assert 89 in _lines(self.findings, "rce")

    def test_dynamic_new_is_code_injection(self):
        assert 91 in _lines(self.findings, "code_injection")

    def test_extract_and_parse_str(self):
        assert {94, 95} <= _lines(self.findings, "variable_overwrite")
        assert 96 not in _lines(self.findings, "variable_overwrite")

    def test_xpath_injection_without_sql_duplicate(self):
        assert 100 in _lines(self.findings, "xpath_injection")
        assert 100 not in _lines(self.findings, "sql_injection")

    def test_unserialize_with_allowed_classes_false(self):
        assert 103 not in _lines(self.findings, "insecure_deserialization")


class TestWordPressPlugin:
    """wordpress/plugin.php - $wpdb, esc_*, sanitize_*, hooks, closures, contexte admin."""

    @pytest.fixture(autouse=True)
    def _scan(self, scan_file_full):
        self.findings = scan_file_full("wordpress/plugin.php")

    def test_sqli_in_hook_closure(self):
        f = [x for x in _by_line(self.findings, 15) if x.vuln_type == "sql_injection"]
        assert f and f[0].confidence.name == "HIGH"

    def test_wpdb_prepare_with_placeholders_is_safe(self):
        assert 22 not in _lines(self.findings, "sql_injection")

    def test_tainted_prepare_format_is_flagged(self):
        assert 31 in _lines(self.findings, "sql_injection")

    def test_array_map_intval_is_safe(self):
        assert 37 not in _lines(self.findings, "sql_injection")

    def test_xss_escaping_functions(self):
        xss = _lines(self.findings, "xss")
        assert 44 in xss and 47 in xss
        assert 45 not in xss and 46 not in xss and 50 not in xss

    def test_redirects(self):
        assert 59 in _lines(self.findings, "open_redirect")
        assert 55 not in _lines(self.findings, "open_redirect")

    def test_ssrf_wp_remote_get_vs_safe(self):
        assert 66 in _lines(self.findings, "ssrf")
        assert 67 not in _lines(self.findings, "ssrf")

    def test_maybe_unserialize(self):
        assert 73 in _lines(self.findings, "insecure_deserialization")

    def test_get_template_part(self):
        assert 78 in _lines(self.findings, "file_inclusion")
        assert 80 not in _lines(self.findings, "file_inclusion")

    def test_privileged_context_downgrades(self):
        f = [x for x in _by_line(self.findings, 89) if x.vuln_type == "rce"]
        assert f and "privileged-context" in f[0].tags
        assert f[0].severity.name == "HIGH"  # critical -> high

    def test_dynamic_callbacks(self):
        assert {94, 96} <= _lines(self.findings, "code_injection")

    def test_absint_sanitizes(self):
        assert 104 in _lines(self.findings, "sql_injection")
        assert 106 not in _lines(self.findings, "sql_injection")

    def test_wp_mail_headers(self):
        assert 112 in _lines(self.findings, "email_injection")


class TestWordPressTemplate:
    """wordpress/template.php - syntaxe alternative, <?= ?>, statements sans accolades."""

    @pytest.fixture(autouse=True)
    def _scan(self, scan_file_full):
        self.findings = scan_file_full("wordpress/template.php")

    def test_short_echo_tag(self):
        assert 7 in _lines(self.findings, "xss")
        assert 8 not in _lines(self.findings, "xss")

    def test_elseif_colon_block(self):
        assert 10 in _lines(self.findings, "xss")

    def test_foreach_colon_block(self):
        assert 17 in _lines(self.findings, "xss")
        assert 16 not in _lines(self.findings, "xss")

    def test_single_statement_if(self):
        assert 21 in _lines(self.findings, "xss")


class TestLaravelController:
    """frameworks/LaravelController.php - objets requete, facades, helpers."""

    @pytest.fixture(autouse=True)
    def _scan(self, scan_file_full):
        self.findings = scan_file_full("frameworks/LaravelController.php")

    def test_request_input_to_db_select(self):
        assert 13 in _lines(self.findings, "sql_injection")

    def test_bound_parameters_are_safe(self):
        assert 20 not in _lines(self.findings, "sql_injection")

    def test_where_raw_with_request_helper(self):
        assert 27 in _lines(self.findings, "sql_injection")

    def test_redirect_helper(self):
        assert 33 in _lines(self.findings, "open_redirect")

    def test_request_magic_property_and_e_helper(self):
        assert 39 in _lines(self.findings, "xss")
        assert 40 not in _lines(self.findings, "xss")

    def test_storage_facade(self):
        assert 46 in _lines(self.findings, "path_traversal")


class TestTaintParamsMode:
    """--taint-params : parametres de fonctions jamais appelees."""

    def test_uncalled_function_params_reported_low_confidence(self, rules, tmp_path):
        from config.schema import ScanConfig, Confidence
        from scanner import Scanner

        (tmp_path / "handlers.php").write_text(
            "<?php\n"
            "function ajax_handler($id) {\n"
            "    mysqli_query($GLOBALS['db'], 'SELECT * FROM t WHERE id = ' . $id);\n"   # line 3
            "}\n"
            "function guarded_handler($slug) {\n"
            "    if (!preg_match('/^[a-z]+$/', $slug)) { exit; }\n"
            "    readfile('/srv/' . $slug);\n"                                             # line 7 (safe)
            "}\n"
            "function called_handler($x) { echo $x; }\n"                                 # line 9 (called)
            "called_handler('static');\n"
        )
        config = ScanConfig(
            project_path=tmp_path,
            vuln_types=rules.get_vuln_types(),
            rules=rules,
            show_progress=False,
            no_color=True,
            taint_params=True,
        )
        result = Scanner(config).run()
        extra = [f for f in result.findings if "uncalled-entry-point" in f.tags]
        assert [(f.line, f.vuln_type) for f in extra] == [(3, "sql_injection")], [
            (f.line, f.vuln_type, f.tags) for f in result.findings
        ]
        assert extra[0].confidence == Confidence.LOW
        assert "ajax_handler" in extra[0].title

    def test_without_flag_nothing_reported(self, rules, tmp_path):
        from config.schema import ScanConfig
        from scanner import Scanner

        (tmp_path / "h.php").write_text("<?php function h($id) { mysqli_query($c, 'x' . $id); }\n")
        config = ScanConfig(project_path=tmp_path, vuln_types=rules.get_vuln_types(), rules=rules,
                            show_progress=False, no_color=True)
        assert Scanner(config).run().findings == []


class TestNoFalsePositives:
    """Cas sans finding attendu."""

    def test_sink_result_is_not_a_source(self, scan_file_full):
        """echo file_get_contents($url) : ssrf oui, xss non (resultat de sink opaque)."""
        findings = scan_file_full("scripts/ssrf.php")
        assert "xss" not in {f.vuln_type for f in findings}

    def test_file_put_contents_content_is_not_path_traversal(self, scan_file_full):
        findings = scan_file_full("app/ApiHandler.php")
        assert 102 not in _lines(findings, "path_traversal")

    def test_move_uploaded_file_reported_once(self, scan_file_full):
        findings = scan_file_full("scripts/insecure_upload.php")
        assert _lines(findings, "path_traversal") == set()
        assert {4, 7} <= _lines(findings, "insecure_upload")
