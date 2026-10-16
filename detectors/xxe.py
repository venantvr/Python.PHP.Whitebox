# detectors/xxe.py
from detectors.base import BaseDetector
from report.finding import Finding


class XXEDetector(BaseDetector):
    """Supprime le finding si libxml_disable_entity_loader(true) est present.
    La confiance est ajustee par ContextAnalyzer selon LIBXML_NOENT."""
    vuln_type = "xxe"

    def accept(self, finding: Finding, source: str) -> bool:
        if "libxml_disable_entity_loader(true)" in source.replace(" ", ""):
            return False
        return True
