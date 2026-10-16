# detectors/session_fixation.py
from detectors.base import BaseDetector


class SessionFixationDetector(BaseDetector):
    """session_id($userInput) : session_regenerate_id() ailleurs dans le fichier
    ne corrige pas le probleme, le finding est conserve."""
    vuln_type = "session_fixation"
