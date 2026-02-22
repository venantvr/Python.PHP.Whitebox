# parser/scope_analyzer.py - Extract function, class and method scopes from a PHP AST

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from utils.text import get_node_text

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FunctionSignature:
    """Metadata for a single PHP function or method."""

    name: str
    file_path: str
    parameters: list[str] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0
    node: Optional[object] = field(default=None, repr=False)
    is_method: bool = False
    class_name: Optional[str] = None


@dataclass
class ClassInfo:
    """Metadata for a single PHP class declaration."""

    name: str
    file_path: str
    methods: list[FunctionSignature] = field(default_factory=list)
    parent_class: Optional[str] = None
    start_line: int = 0


@dataclass
class FileScopes:
    """All scopes discovered in a single PHP file."""

    file_path: str
    functions: list[FunctionSignature] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    global_node: Optional[object] = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Scope analyser
# ---------------------------------------------------------------------------

class ScopeAnalyzer:
    """Walk a tree-sitter PHP AST and extract scope information.

    Usage::

        analyzer = ScopeAnalyzer()
        scopes = analyzer.extract(tree, source_code, "/path/to/file.php")
    """

    def extract(self, tree, source: str, file_path: str) -> FileScopes:
        """Extract all scopes from a parsed tree-sitter *tree*.

        Parameters
        ----------
        tree:
            A ``tree_sitter.Tree`` obtained from ``Parser.parse()``.
        source:
            The PHP source code as a Python *str*.
        file_path:
            Absolute path of the file being analysed (stored on the
            returned dataclasses for later reporting).

        Returns
        -------
        FileScopes
            Aggregated scope information for the file.
        """
        source_bytes: bytes = source.encode("utf-8")
        root = tree.root_node

        scopes = FileScopes(
            file_path=file_path,
            global_node=root,
        )

        for child in root.children:
            if child.type == "function_definition":
                sig = self._extract_function(child, source_bytes, file_path)
                if sig is not None:
                    scopes.functions.append(sig)

            elif child.type == "class_declaration":
                cls = self._extract_class(child, source_bytes, file_path)
                if cls is not None:
                    scopes.classes.append(cls)

        return scopes

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_function(
        self,
        node,
        source_bytes: bytes,
        file_path: str,
        *,
        is_method: bool = False,
        class_name: Optional[str] = None,
    ) -> Optional[FunctionSignature]:
        """Build a ``FunctionSignature`` from a function/method AST node."""
        name_node = node.child_by_field_name("name")
        if name_node is None:
            logger.debug(
                "Skipping anonymous function at line %d in %s",
                node.start_point[0] + 1,
                file_path,
            )
            return None

        name = get_node_text(name_node, source_bytes)
        parameters = self._extract_parameters(node, source_bytes)

        return FunctionSignature(
            name=name,
            file_path=file_path,
            parameters=parameters,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            node=node,
            is_method=is_method,
            class_name=class_name,
        )

    def _extract_class(
        self,
        node,
        source_bytes: bytes,
        file_path: str,
    ) -> Optional[ClassInfo]:
        """Build a ``ClassInfo`` from a class_declaration AST node."""
        name_node = node.child_by_field_name("name")
        if name_node is None:
            logger.debug(
                "Skipping anonymous class at line %d in %s",
                node.start_point[0] + 1,
                file_path,
            )
            return None

        class_name = get_node_text(name_node, source_bytes)

        # Detect parent class (``class Foo extends Bar``)
        parent_class: Optional[str] = None
        base_clause = node.child_by_field_name("base_clause")
        if base_clause is not None:
            # base_clause children: "extends" keyword, then the class name.
            for child in base_clause.named_children:
                if child.type == "name":
                    parent_class = get_node_text(child, source_bytes)
                    break

        # Collect methods from the declaration_list body.
        methods: list[FunctionSignature] = []
        body = node.child_by_field_name("body")
        if body is not None:
            for member in body.children:
                if member.type == "method_declaration":
                    sig = self._extract_function(
                        member,
                        source_bytes,
                        file_path,
                        is_method=True,
                        class_name=class_name,
                    )
                    if sig is not None:
                        methods.append(sig)

        return ClassInfo(
            name=class_name,
            file_path=file_path,
            methods=methods,
            parent_class=parent_class,
            start_line=node.start_point[0] + 1,
        )

    @staticmethod
    def _extract_parameters(func_node, source_bytes: bytes) -> list[str]:
        """Return a list of parameter name strings (including the ``$`` sigil).

        Handles both ``function_definition`` and ``method_declaration`` nodes
        by looking for ``formal_parameters`` -> ``simple_parameter`` children.
        """
        params: list[str] = []
        params_node = func_node.child_by_field_name("parameters")
        if params_node is None:
            return params

        for child in params_node.children:
            if child.type == "simple_parameter":
                # The parameter name is the ``name`` field on the node,
                # which is a ``variable_name`` node (e.g. ``$id``).
                name_node = child.child_by_field_name("name")
                if name_node is not None:
                    params.append(get_node_text(name_node, source_bytes))
            elif child.type == "variadic_parameter":
                name_node = child.child_by_field_name("name")
                if name_node is not None:
                    params.append("..." + get_node_text(name_node, source_bytes))
        return params
