# utils/filewalker.py - Recherche recursive de fichiers PHP avec exclusions

import os
import fnmatch
from pathlib import Path

# Patterns exclus par defaut
DEFAULT_EXCLUDES = [
    "vendor/*",
    "node_modules/*",
    ".git/*",
    ".svn/*",
    "__pycache__/*",
    ".venv/*",
]


def find_php_files(root_dir, exclude_patterns=None):
    """Trouve recursivement tous les fichiers .php dans root_dir.

    Parameters
    ----------
    root_dir : str or Path
        Repertoire racine a scanner.
    exclude_patterns : list[str], optional
        Patterns glob a exclure (ex: ['vendor/*', 'tests/*']).
        Les patterns par defaut (vendor, node_modules, .git) sont toujours appliques.

    Returns
    -------
    list[str]
        Liste des chemins absolus des fichiers PHP trouves.
    """
    root = str(root_dir)
    excludes = list(DEFAULT_EXCLUDES)
    if exclude_patterns:
        excludes.extend(exclude_patterns)

    php_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Calculer le chemin relatif pour le matching
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""

        # Filtrer les repertoires exclus
        dirnames[:] = [
            d for d in dirnames
            if not _is_excluded(os.path.join(rel_dir, d) if rel_dir else d, excludes)
        ]

        for f in filenames:
            if not f.endswith(".php"):
                continue
            rel_path = os.path.join(rel_dir, f) if rel_dir else f
            if not _is_excluded(rel_path, excludes):
                php_files.append(os.path.join(dirpath, f))

    return php_files


def _is_excluded(rel_path: str, patterns: list[str]) -> bool:
    """Verifie si un chemin relatif match un des patterns d'exclusion."""
    for pattern in patterns:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        # Aussi verifier chaque segment du chemin
        parts = rel_path.replace("\\", "/").split("/")
        for part in parts:
            if fnmatch.fnmatch(part, pattern.rstrip("/*")):
                return True
    return False
