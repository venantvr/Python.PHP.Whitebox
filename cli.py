# cli.py - Point d'entree CLI pour Python.PHP.Whitebox

import argparse
import sys
from pathlib import Path

VULN_TYPES = [
    "sql_injection",
    "xss",
    "rce",
    "code_injection",
    "file_inclusion",
    "path_traversal",
    "insecure_upload",
    "insecure_deserialization",
    "ssrf",
    "xxe",
    "open_redirect",
    "ldap_injection",
    "crypto_weakness",
    "hardcoded_secrets",
    "session_fixation",
    "type_juggling",
]

SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]


def parse_args():
    parser = argparse.ArgumentParser(
        prog="Python.PHP.Whitebox",
        description="Python.PHP.Whitebox - Analyse statique de securite pour projets PHP (white-box)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python3 -m cli /var/www/monprojet/
  python3 -m cli /var/www/monprojet/ --vuln-types sql_injection xss --format json
  python3 -m cli /var/www/monprojet/ --severity-min high --format html -o report.html
  python3 -m cli /var/www/monprojet/ --exclude "vendor/*" "tests/*"
        """,
    )

    parser.add_argument(
        "path",
        type=Path,
        help="Chemin vers le repertoire du projet PHP a analyser",
    )
    parser.add_argument(
        "--vuln-types",
        nargs="+",
        choices=VULN_TYPES,
        default=None,
        help="Types de vulnerabilites a rechercher (defaut: tous)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "html"],
        default="terminal",
        help="Format de sortie (defaut: terminal)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Fichier de sortie (defaut: stdout pour terminal, report.json/html sinon)",
    )
    parser.add_argument(
        "--severity-min",
        choices=SEVERITY_LEVELS,
        default="info",
        help="Severite minimale a reporter (defaut: info = tout)",
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        default=[],
        help="Patterns d'exclusion (ex: vendor/* tests/*)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Chemin vers un fichier de regles YAML custom",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Scan precedent pour comparaison (affiche uniquement les nouveaux findings)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Desactiver les couleurs dans la sortie terminal",
    )

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Mode verbeux (debug)",
    )
    verbosity.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Mode silencieux",
    )

    return parser.parse_args()


def run():
    args = parse_args()

    # Validation
    if not args.path.is_dir():
        print(f"Erreur: {args.path} n'est pas un repertoire", file=sys.stderr)
        sys.exit(1)

    # Charger les regles
    from config.loader import load_rules
    from config.schema import ScanConfig, Severity

    config_path = str(args.config) if args.config else "config/rules.yaml"
    rules = load_rules(config_path)

    vuln_types = args.vuln_types or rules.get_vuln_types()

    # Verbosity
    if args.verbose:
        verbosity = "debug"
    elif args.quiet:
        verbosity = "quiet"
    else:
        verbosity = "normal"

    config = ScanConfig(
        project_path=args.path.resolve(),
        vuln_types=vuln_types,
        rules=rules,
        severity_min=args.severity_min,
        exclude_patterns=args.exclude,
        output_path=args.output,
        output_format=args.format,
        no_color=args.no_color,
        baseline_path=args.baseline,
        verbosity=verbosity,
        show_progress=(verbosity != "quiet"),
    )

    # Scanner
    from scanner import Scanner
    scanner = Scanner(config)
    result = scanner.run()

    # Filtre par severite
    sev_min = Severity.from_str(args.severity_min)
    result.findings = [f for f in result.findings if f.severity >= sev_min]

    # Filtre par baseline
    if args.baseline:
        from report.baseline import BaselineComparator
        comparator = BaselineComparator(args.baseline)
        result.findings = comparator.filter_new(result.findings)

    # Recalculer le summary apres filtrage
    from report.finding import compute_summary
    result.summary = compute_summary(result.findings, result.files_scanned)

    # Reporter
    from report import generate_report
    output_str = str(args.output) if args.output else None
    generate_report(result, args.format, output_str, no_color=args.no_color)

    # Exit code
    sys.exit(1 if result.findings else 0)


if __name__ == "__main__":
    run()
