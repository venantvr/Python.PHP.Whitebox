# cli.py - Point d'entree CLI pour Python.PHP.Whitebox

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]
CONFIDENCE_LEVELS = ["low", "medium", "high"]


def _available_vuln_types(config_path=None) -> list[str]:
    try:
        from config.loader import load_rules
        return load_rules(config_path).get_vuln_types() + ["dangerous_config"]
    except Exception:
        return []


def parse_args(argv=None):
    # Pre-parse --config pour lister les types disponibles dans l'aide
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", type=Path, default=None)
    pre_args, _ = pre.parse_known_args(argv)
    vuln_types = _available_vuln_types(str(pre_args.config) if pre_args.config else None)

    parser = argparse.ArgumentParser(
        prog="Python.PHP.Whitebox",
        description="Python.PHP.Whitebox - Analyse statique de securite pour projets PHP (white-box). "
                    "PHP generique + WordPress + frameworks (Laravel, Symfony, CodeIgniter, PSR-7).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Types de vulnerabilites : {', '.join(vuln_types) if vuln_types else '(voir config/rules.yaml)'}

Exemples:
  python3 -m cli /var/www/monprojet/
  python3 -m cli wp-content/plugins/mon-plugin --format html -o report.html
  python3 -m cli /var/www/monprojet/ --vuln-types sql_injection xss --format json
  python3 -m cli /var/www/monprojet/ --severity-min high --confidence-min medium
  python3 -m cli /var/www/wordpress --exclude "wp-admin/*" "wp-includes/*" --taint-params
  python3 -m cli . --format sarif -o results.sarif --fail-on high
        """,
    )

    parser.add_argument(
        "path",
        type=Path,
        help="Chemin vers le repertoire (ou fichier) PHP a analyser",
    )
    parser.add_argument(
        "--vuln-types",
        nargs="+",
        choices=vuln_types or None,
        metavar="TYPE",
        default=None,
        help="Types de vulnerabilites a rechercher (defaut: tous)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "sarif", "html"],
        default="terminal",
        help="Format de sortie (defaut: terminal ; sarif = json SARIF 2.1.0)",
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
        "--confidence-min",
        choices=CONFIDENCE_LEVELS,
        default="low",
        help="Confiance minimale a reporter (defaut: low = tout). 'medium' elimine les flux via methodes inconnues.",
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        default=[],
        metavar="PATTERN",
        help="Patterns d'exclusion (ex: vendor/* tests/* wp-includes/*)",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=None,
        metavar="EXT",
        help="Extensions a analyser (defaut: .php .phtml .inc .module .theme .install ...)",
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
        help="Scan precedent (JSON) pour comparaison : affiche uniquement les nouveaux findings",
    )
    parser.add_argument(
        "--taint-params",
        action="store_true",
        help="Considerer les parametres des fonctions jamais appelees (hooks, controleurs, API) "
             "comme controles par l'utilisateur (findings a confiance basse)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none"] + SEVERITY_LEVELS,
        default="info",
        help="Code de sortie 1 si un finding atteint cette severite (defaut: info = tout finding ; none = toujours 0)",
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

    return parser.parse_args(argv)


def run(argv=None):
    args = parse_args(argv)

    if not args.path.exists():
        print(f"Erreur: {args.path} n'existe pas", file=sys.stderr)
        sys.exit(2)

    from config.loader import load_rules, validate_rules
    from config.schema import ScanConfig, Severity

    rules = load_rules(str(args.config) if args.config else None)
    rule_errors = validate_rules(rules)
    if rule_errors:
        for err in rule_errors:
            print(f"Avertissement regles: {err}", file=sys.stderr)

    vuln_types = args.vuln_types or rules.get_vuln_types()

    if args.verbose:
        verbosity = "debug"
    elif args.quiet:
        verbosity = "quiet"
    else:
        verbosity = "normal"

    output_format = "json" if args.format == "sarif" else args.format

    config = ScanConfig(
        project_path=args.path.resolve(),
        vuln_types=vuln_types,
        rules=rules,
        severity_min=args.severity_min,
        confidence_min=args.confidence_min,
        exclude_patterns=args.exclude,
        output_path=args.output,
        output_format=output_format,
        no_color=args.no_color,
        baseline_path=args.baseline,
        verbosity=verbosity,
        show_progress=(verbosity != "quiet"),
        extensions=args.extensions,
        taint_params=args.taint_params,
    )

    from scanner import Scanner
    scanner = Scanner(config)
    result = scanner.run()

    sev_min = Severity.from_str(args.severity_min)
    result.findings = [f for f in result.findings if f.severity >= sev_min]

    if args.baseline:
        from report.baseline import BaselineComparator
        comparator = BaselineComparator(args.baseline)
        result.findings = comparator.filter_new(result.findings)

    from report.finding import compute_summary
    result.summary = compute_summary(result.findings, result.files_scanned)

    from report import generate_report
    output_str = str(args.output) if args.output else None
    generate_report(result, output_format, output_str, no_color=args.no_color)

    if args.fail_on == "none":
        sys.exit(0)
    fail_sev = Severity.from_str(args.fail_on)
    sys.exit(1 if any(f.severity >= fail_sev for f in result.findings) else 0)


if __name__ == "__main__":
    run()
