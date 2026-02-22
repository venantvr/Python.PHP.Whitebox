# parser/include_resolver.py - Resolve PHP include/require statements from an AST

from __future__ import annotations

import logging
from pathlib import Path
from typing import Union

from utils.text import get_node_text

logger = logging.getLogger(__name__)

# Tree-sitter PHP node types that represent include/require statements.
_INCLUDE_NODE_TYPES: frozenset[str] = frozenset({
    "include_expression",
    "include_once_expression",
    "require_expression",
    "require_once_expression",
})


class IncludeResolver:
    """Resolve ``include`` / ``require`` paths found in a PHP AST.

    Only *statically determinable* paths (string literals) are resolved.
    Dynamic paths that involve variables or concatenation are silently
    skipped because they cannot be evaluated without running the code.

    Parameters
    ----------
    project_root:
        Absolute path to the root directory of the PHP project being
        scanned.  Used as a fallback base when the included path cannot
        be resolved relative to the including file.
    """

    def __init__(self, project_root: Union[str, Path]) -> None:
        self.project_root: Path = Path(project_root).resolve()

    def find_includes(self, tree, source: str, file_path: str) -> list[str]:
        """Walk the AST and return resolved absolute paths of included files.

        Parameters
        ----------
        tree:
            A ``tree_sitter.Tree`` for the PHP file.
        source:
            The PHP source code as a Python *str*.
        file_path:
            Absolute path of the file currently being analysed.  Relative
            include paths are resolved against this file's directory first.

        Returns
        -------
        list[str]
            Deduplicated list of absolute paths (as strings) that could be
            resolved on disk.  Paths that do not point to an existing file
            are omitted.
        """
        source_bytes: bytes = source.encode("utf-8")
        including_dir = Path(file_path).resolve().parent

        seen: set[str] = set()
        results: list[str] = []

        self._walk(tree.root_node, source_bytes, including_dir, seen, results)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _walk(
        self,
        node,
        source_bytes: bytes,
        including_dir: Path,
        seen: set[str],
        results: list[str],
    ) -> None:
        """Recursively walk the AST looking for include/require nodes."""
        if node.type in _INCLUDE_NODE_TYPES:
            resolved = self._resolve_include(node, source_bytes, including_dir)
            if resolved is not None:
                resolved_str = str(resolved)
                if resolved_str not in seen:
                    seen.add(resolved_str)
                    results.append(resolved_str)

        for child in node.children:
            self._walk(child, source_bytes, including_dir, seen, results)

    def _resolve_include(
        self,
        node,
        source_bytes: bytes,
        including_dir: Path,
    ) -> Path | None:
        """Try to resolve the include path from a single include/require node.

        The expected node structure is::

            include_expression
              "include"          (keyword)
              <expression>       (the path argument)

        We only handle the case where the expression is a ``string``
        (single- or double-quoted literal).  Anything else (variable,
        concatenation, function call) is treated as dynamic and skipped.
        """
        # The path argument is the second child (index 1) -- the first
        # child is the keyword itself ("include", "require", etc.).
        if node.named_child_count < 1:
            return None

        # Use the first *named* child (skips keyword tokens).
        path_node = node.named_children[0]

        # Parenthesised expression: ``include("foo.php")``
        if path_node.type == "parenthesized_expression" and path_node.named_child_count > 0:
            path_node = path_node.named_children[0]

        # We only handle plain string literals.
        if path_node.type not in ("string", "encapsed_string"):
            logger.debug(
                "Skipping dynamic include at line %d (node type: %s)",
                node.start_point[0] + 1,
                path_node.type,
            )
            return None

        raw_text = get_node_text(path_node, source_bytes)

        # Strip surrounding quotes (single or double).
        path_str = raw_text.strip("'\"")
        if not path_str:
            return None

        # Replace common PHP constants that we can approximate.
        # __DIR__ is the directory of the *including* file.
        path_str = path_str.replace("__DIR__", str(including_dir))

        # Attempt resolution:
        # 1. Relative to the including file's directory.
        candidate = (including_dir / path_str).resolve()
        if candidate.is_file():
            return candidate

        # 2. Relative to the project root.
        candidate = (self.project_root / path_str).resolve()
        if candidate.is_file():
            return candidate

        logger.debug(
            "Could not resolve include path '%s' (from line %d)",
            path_str,
            node.start_point[0] + 1,
        )
        return None
