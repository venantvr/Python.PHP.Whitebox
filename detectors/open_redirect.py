# detectors/open_redirect.py
from detectors.base import BaseDetector


class OpenRedirectDetector(BaseDetector):
    """Le TaintTracker ne signale header() que pour Location:/Refresh: ;
    les autres sinks (wp_redirect, redirect()...) sont toujours pertinents."""
    vuln_type = "open_redirect"
