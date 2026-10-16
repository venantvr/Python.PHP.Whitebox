# detectors/hardcoded_secrets.py
from detectors.base import BaseDetector
from report.finding import Finding


class HardcodedSecretsDetector(BaseDetector):
    vuln_type = "hardcoded_secrets"

    def accept(self, finding: Finding, source: str) -> bool:
        snippet = (finding.code_snippet or "").strip()
        # Commentaires / exemples
        if snippet.startswith(("//", "*", "#", "/*")):
            return False
        # Valeur lue depuis l'environnement sur la meme ligne
        if "getenv(" in snippet or "$_ENV" in snippet or "env(" in snippet:
            return False
        return True
