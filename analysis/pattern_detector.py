# analysis/pattern_detector.py - Detection par regex (secrets, crypto, configs)

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from config.schema import Severity, Confidence
from report.finding import Finding

if TYPE_CHECKING:
    from config.loader import RulesConfig


# Valeurs de secrets manifestement factices (placeholders, exemples, tests)
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(\*+|x+|\.+|-+|_+|#+|\?+|changeme|change[_-]?me|change[_-]?this|password|passw0rd|pass|secret|"
    r"your[_ -]?\w*|my[_ -]?(password|secret|key|token)|<[^>]+>|\{\{.*\}\}|\$\{.*\}|%[^%]+%|\[[^\]]+\]|"
    r"put your unique phrase here|example\w*|sample\w*|test\w*|dummy\w*|placeholder|null|none|todo|"
    r"xxx+|123456?|12345678|admin|root|toor|password123|p@ssw0rd|qwerty|letmein|__[A-Z_]+__|"
    r"\.\.\.|insert[_ -]?\w*|replace[_ -]?\w*|enter[_ -]?\w*|\{[a-z_]+\}|\$[a-z_]+|[a-z_]+\(\))$"
)


@dataclass
class _CompiledPattern:
    regex: re.Pattern
    vuln_type: str
    message: str
    severity: Severity
    cwe: str
    remediation: str
    confidence: Confidence = Confidence.LOW
    owasp: str = ""


class PatternDetector:
    """Detecteur de patterns regex pour les vulns non liees au flux de donnees.

    Complementaire au TaintTracker : detecte les hardcoded secrets, algorithmes
    crypto faibles, et configurations dangereuses par matching regex ligne par
    ligne. Les commentaires sont retires avant le matching (via l'AST si fourni).
    Les findings produits ont detection_mode="pattern" et confidence=LOW par
    defaut (pas de preuve de flux de donnees).
    """

    def __init__(self, rules: "RulesConfig"):
        self.rules = rules
        self._compiled: list[_CompiledPattern] = []
        self._compile_all()

    def _compile_all(self):
        for vuln_type, rule in self.rules.vulnerabilities.items():
            if rule.detection_mode != "pattern":
                continue
            for p in rule.patterns:
                try:
                    regex = re.compile(p["pattern"])
                except re.error:
                    continue
                self._compiled.append(_CompiledPattern(
                    regex=regex,
                    vuln_type=vuln_type,
                    message=p.get("message", rule.description),
                    severity=Severity.from_str(p["severity"]) if p.get("severity") else rule.severity,
                    cwe=p.get("cwe", rule.cwe),
                    remediation=rule.remediation,
                    confidence=Confidence.from_str(p["confidence"]) if p.get("confidence") else Confidence.LOW,
                    owasp=rule.owasp,
                ))

        for cfg in self.rules.dangerous_configs:
            try:
                regex = re.compile(cfg["pattern"])
            except re.error:
                continue
            self._compiled.append(_CompiledPattern(
                regex=regex,
                vuln_type="dangerous_config",
                message=cfg.get("message", "Dangerous configuration"),
                severity=Severity.from_str(cfg.get("severity", "medium")),
                cwe=cfg.get("cwe", ""),
                remediation=cfg.get("remediation", "Review this setting; disable it in production."),
                confidence=Confidence.from_str(cfg.get("confidence", "medium")),
                owasp="A05:2021 - Security Misconfiguration",
            ))

    def scan_file(self, file_path: str, source_code: str, tree=None) -> list[Finding]:
        """Scanne un fichier source ligne par ligne pour les patterns.

        Si `tree` (AST tree-sitter) est fourni, les commentaires sont effaces
        avant le matching pour eviter les faux positifs sur les exemples.
        """
        code = self._strip_comments(source_code, tree) if tree is not None else source_code
        lines = code.splitlines()
        original_lines = source_code.splitlines()
        findings: list[Finding] = []
        best: dict[tuple[int, str], Finding] = {}

        for line_no, line in enumerate(lines, 1):
            if not line.strip():
                continue
            for cp in self._compiled:
                m = cp.regex.search(line)
                if not m:
                    continue
                if cp.vuln_type == "hardcoded_secrets" and self._is_placeholder(m):
                    continue
                snippet = original_lines[line_no - 1].strip() if line_no - 1 < len(original_lines) else line.strip()
                finding = Finding(
                    vuln_type=cp.vuln_type,
                    severity=cp.severity,
                    confidence=cp.confidence,
                    cwe=cp.cwe,
                    owasp=cp.owasp,
                    title=cp.message,
                    description=cp.message,
                    file_path=file_path,
                    line=line_no,
                    column=m.start() + 1,
                    code_snippet=snippet,
                    remediation=cp.remediation,
                    detection_mode="pattern",
                )
                key = (line_no, cp.vuln_type)
                prev = best.get(key)
                if prev is None or finding.severity > prev.severity:
                    best[key] = finding

        for key in sorted(best):
            findings.append(best[key])
        return findings

    @staticmethod
    def _is_placeholder(match: re.Match) -> bool:
        try:
            value = match.group("value")
        except IndexError:
            return False
        if value is None:
            return False
        value = value.strip()
        if not value:
            return True
        return bool(_PLACEHOLDER_RE.match(value))

    @staticmethod
    def _strip_comments(source: str, tree) -> str:
        """Remplace les commentaires par des espaces (conserve les positions/lignes)."""
        data = bytearray(source.encode("utf-8"))
        changed = False

        def visit(node):
            nonlocal changed
            if node.type == "comment":
                for i in range(node.start_byte, min(node.end_byte, len(data))):
                    if data[i] not in (0x0A, 0x0D):
                        data[i] = 0x20
                changed = True
                return
            for child in node.children:
                visit(child)

        visit(tree.root_node)
        if not changed:
            return source
        return data.decode("utf-8", errors="replace")
