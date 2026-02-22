# report/json_reporter.py - SARIF v2.1.0 JSON reporter for Python.PHP.Whitebox

from __future__ import annotations

import json
from typing import Optional

from config.schema import Severity
from report.finding import ScanResult, Finding


# ---------------------------------------------------------------------------
# SARIF severity mapping
# ---------------------------------------------------------------------------

_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
}

_SARIF_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH:     "high",
    Severity.MEDIUM:   "medium",
    Severity.LOW:      "low",
    Severity.INFO:     "informational",
}


class JSONReporter:
    """Generates a SARIF v2.1.0 compatible JSON report."""

    def report(self, result: ScanResult, output_path: Optional[str] = None) -> str:
        """Render the scan result as SARIF JSON and write to *output_path*.

        Returns:
            The path of the generated report file.
        """
        sarif = self._build_sarif(result)
        path = output_path or "report.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, ensure_ascii=False)
        return path

    # ------------------------------------------------------------------
    # SARIF document builder
    # ------------------------------------------------------------------

    def _build_sarif(self, result: ScanResult) -> dict:
        rules_map: dict[str, dict] = {}
        sarif_results: list[dict] = []

        for finding in result.findings:
            rule = self._ensure_rule(rules_map, finding)
            sarif_results.append(self._build_result(finding))

        run: dict = {
            "tool": {
                "driver": {
                    "name": "Python.PHP.Whitebox",
                    "version": result.scanner_version,
                    "informationUri": "https://github.com/PHP-Sec-Scan/Python.PHP.Whitebox",
                    "rules": list(rules_map.values()),
                },
            },
            "results": sarif_results,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "startTimeUtc": result.timestamp,
                },
            ],
            "properties": {
                "phpsecscan": self._build_custom_summary(result),
            },
        }

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [run],
        }

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def _ensure_rule(self, rules_map: dict[str, dict], finding: Finding) -> dict:
        rule_id = self._rule_id(finding)
        if rule_id in rules_map:
            return rules_map[rule_id]

        rule: dict = {
            "id": rule_id,
            "name": finding.vuln_type,
            "shortDescription": {
                "text": finding.title,
            },
            "fullDescription": {
                "text": finding.description or finding.title,
            },
            "helpUri": f"https://cwe.mitre.org/data/definitions/{self._cwe_number(finding.cwe)}.html",
            "help": {
                "text": finding.remediation or "No remediation guidance available.",
                "markdown": finding.remediation or "No remediation guidance available.",
            },
            "properties": {
                "tags": [
                    finding.cwe,
                    finding.owasp,
                    finding.vuln_type,
                ],
                "security-severity": str(self._security_severity_score(finding.severity)),
            },
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
            },
        }
        rules_map[rule_id] = rule
        return rule

    # ------------------------------------------------------------------
    # Individual result
    # ------------------------------------------------------------------

    def _build_result(self, finding: Finding) -> dict:
        result: dict = {
            "ruleId": self._rule_id(finding),
            "level": _SARIF_LEVEL.get(finding.severity, "warning"),
            "message": {
                "text": finding.description or finding.title,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line,
                            "startColumn": finding.column or 1,
                        },
                    },
                },
            ],
            "fingerprints": {
                "phpsecscan/v1": finding.fingerprint,
            },
            "properties": {
                "severity": finding.severity.name.lower(),
                "confidence": finding.confidence.name.lower(),
                "detectionMode": finding.detection_mode,
                "sinkFunction": finding.sink_function,
                "sourceVariable": finding.source_variable,
            },
        }

        # Code snippet as related location
        if finding.code_snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.code_snippet,
            }

        # Code flows (taint trace)
        if finding.data_flow:
            result["codeFlows"] = [self._build_code_flow(finding)]

        return result

    # ------------------------------------------------------------------
    # Code flows
    # ------------------------------------------------------------------

    def _build_code_flow(self, finding: Finding) -> dict:
        thread_flow_locations: list[dict] = []

        for step in finding.data_flow:
            loc: dict = {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": step.file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": step.line,
                            "startColumn": step.column or 1,
                        },
                    },
                    "message": {
                        "text": step.description or f"Step at {step.file}:{step.line}",
                    },
                },
            }
            if step.snippet:
                loc["location"]["physicalLocation"]["region"]["snippet"] = {
                    "text": step.snippet,
                }
            thread_flow_locations.append(loc)

        return {
            "threadFlows": [
                {
                    "locations": thread_flow_locations,
                },
            ],
        }

    # ------------------------------------------------------------------
    # Custom phpsecscan summary
    # ------------------------------------------------------------------

    def _build_custom_summary(self, result: ScanResult) -> dict:
        summary_dict: dict = {}
        if result.summary:
            s = result.summary
            summary_dict = {
                "totalFindings": s.total_findings,
                "bySeverity": s.by_severity,
                "byVulnType": s.by_vuln_type,
                "byConfidence": s.by_confidence,
                "riskScore": s.risk_score,
                "filesWithFindings": s.files_with_findings,
                "filesClean": s.files_clean,
            }

        return {
            "projectPath": result.project_path,
            "scannerVersion": result.scanner_version,
            "timestamp": result.timestamp,
            "scanDurationSeconds": result.scan_duration_seconds,
            "filesScanned": result.files_scanned,
            "totalLines": result.total_lines,
            "summary": summary_dict,
            "errors": result.errors,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rule_id(finding: Finding) -> str:
        """Derive a stable SARIF ruleId from the finding's CWE and vuln type."""
        cwe_part = finding.cwe.replace("-", "").replace(" ", "")
        vuln_slug = finding.vuln_type.replace(" ", "_").replace("-", "_").upper()
        return f"{cwe_part}/{vuln_slug}"

    @staticmethod
    def _cwe_number(cwe: str) -> str:
        """Extract the numeric part from a CWE identifier (e.g. 'CWE-89' -> '89')."""
        parts = cwe.split("-")
        return parts[-1] if len(parts) > 1 else cwe

    @staticmethod
    def _security_severity_score(severity: Severity) -> float:
        """Map Severity to the SARIF security-severity numeric score (0-10)."""
        return {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0,
        }.get(severity, 5.0)
