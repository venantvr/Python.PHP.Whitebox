# utils/filewalker.py - Recherche recursive de fichiers PHP avec exclusions

import os
import fnmatch

# Patterns exclus par defaut
DEFAULT_EXCLUDES = [
    "vendor/*",
    "node_modules/*",
    ".git/*",
    ".svn/*",
    ".hg/*",
    "__pycache__/*",
    ".venv/*",
    "*/uploads/*",
    "*/cache/*",
    "*.min.php",
]

# Extensions PHP reconnues par defaut (WordPress, Drupal, Laravel, legacy...)
DEFAULT_EXTENSIONS = [
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".phps",
    ".inc", ".module", ".theme", ".install", ".profile", ".engine", ".ctp",
]


def find_php_files(root_dir, exclude_patterns=None, extensions=None):
    """Trouve recursivement tous les fichiers PHP dans root_dir.

    Parameters
    ----------
    root_dir : str or Path
        Repertoire racine a scanner (ou fichier unique).
    exclude_patterns : list[str], optional
        Patterns glob a exclure (ex: ['vendor/*', 'tests/*']).
        Les patterns par defaut (vendor, node_modules, .git...) sont toujours appliques.
    extensions : list[str], optional
        Extensions a inclure (defaut: DEFAULT_EXTENSIONS).

    Returns
    -------
    list[str]
        Liste triee des chemins absolus des fichiers PHP trouves.
    """
    root = str(root_dir)
    excludes = list(DEFAULT_EXCLUDES)
    if exclude_patterns:
        excludes.extend(exclude_patterns)
    exts = tuple(e if e.startswith(".") else "." + e for e in (extensions or DEFAULT_EXTENSIONS))

    if os.path.isfile(root):
        return [os.path.abspath(root)]

    php_files = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""

        dirnames[:] = sorted(
            d for d in dirnames
            if not _is_excluded(os.path.join(rel_dir, d) if rel_dir else d, excludes)
        )

        for f in sorted(filenames):
            if not f.lower().endswith(exts):
                continue
            rel_path = os.path.join(rel_dir, f) if rel_dir else f
            if not _is_excluded(rel_path, excludes):
                php_files.append(os.path.join(dirpath, f))

    return php_files


def _is_excluded(rel_path: str, patterns: list[str]) -> bool:
    """Verifie si un chemin relatif match un des patterns d'exclusion."""
    rel_norm = rel_path.replace("\\", "/")
    parts = rel_norm.split("/")
    for pattern in patterns:
        pat = pattern.replace("\\", "/")
        if fnmatch.fnmatch(rel_norm, pat) or fnmatch.fnmatch("/" + rel_norm, pat):
            return True
        # "*/uploads/*" doit aussi matcher "uploads/x.php" a la racine
        if pat.startswith("*/") and fnmatch.fnmatch(rel_norm, pat[2:]):
            return True
        # Verifier chaque segment du chemin (ex: "vendor/*" exclut tout dossier vendor)
        base = pat.rstrip("/*")
        if base and "/" not in base:
            for part in parts[:-1]:
                if fnmatch.fnmatch(part, base):
                    return True
            if pat.endswith("/*") is False and fnmatch.fnmatch(parts[-1], pat):
                return True
    return False
