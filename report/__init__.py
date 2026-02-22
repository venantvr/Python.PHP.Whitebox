# report/__init__.py - Report generation dispatcher

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from report.finding import ScanResult


def generate_report(result: "ScanResult", fmt: str, output_path: Optional[str] = None,
                    no_color: bool = False) -> str:
    """Dispatch report generation to the appropriate reporter.

    Args:
        result: The completed scan result.
        fmt: Output format - one of "json", "html", "terminal".
        output_path: Optional path to write the report file.
        no_color: Disable ANSI colors (terminal reporter only).

    Returns:
        The path to the generated report, or empty string for terminal output.

    Raises:
        ValueError: If the format is not recognized.
    """
    reporters = {
        "json": _get_json_reporter,
        "html": _get_html_reporter,
        "terminal": _get_terminal_reporter,
    }

    factory = reporters.get(fmt.lower())
    if factory is None:
        supported = ", ".join(sorted(reporters.keys()))
        raise ValueError(
            f"Unknown report format: {fmt!r}. Supported formats: {supported}"
        )

    reporter = factory(no_color=no_color)
    return reporter.report(result, output_path=output_path)


def _get_json_reporter(**_kwargs):
    from report.json_reporter import JSONReporter
    return JSONReporter()


def _get_html_reporter(**_kwargs):
    from report.html_reporter import HTMLReporter
    return HTMLReporter()


def _get_terminal_reporter(no_color: bool = False, **_kwargs):
    from report.terminal_reporter import TerminalReporter
    return TerminalReporter(no_color=no_color)
