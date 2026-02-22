# utils/ast_helpers.py - Helpers de navigation pour les AST tree-sitter

from typing import Optional


def get_node_text(node, source_code: bytes) -> str:
    """Extrait le texte d'un noeud AST depuis le code source."""
    return source_code[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def get_argument_nodes(call_node) -> list:
    """Retourne la liste des noeuds arguments d'un function_call_expression."""
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return []
    return [child for child in args_node.named_children if child.type != "comment"]


def get_function_name(call_node, source_code: bytes) -> str:
    """Extrait le nom de la fonction depuis un function_call_expression."""
    func_node = call_node.child_by_field_name("function")
    if func_node is None:
        name_node = call_node.child_by_field_name("name")
        if name_node:
            return get_node_text(name_node, source_code)
        return ""
    return get_node_text(func_node, source_code)


def find_child_by_type(node, node_type: str) -> Optional[object]:
    """Trouve le premier enfant d'un type donne."""
    for child in node.children:
        if child.type == node_type:
            return child
    return None


def find_children_by_type(node, node_type: str) -> list:
    """Trouve tous les enfants d'un type donne."""
    return [child for child in node.children if child.type == node_type]


def get_code_snippet(source: str, line: int, context: int = 2) -> str:
    """Extrait un snippet de code autour d'une ligne donnee."""
    lines = source.splitlines()
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    result = []
    for i in range(start, end):
        prefix = ">>> " if i == line - 1 else "    "
        result.append(f"{prefix}{i + 1}: {lines[i]}")
    return "\n".join(result)


def walk_tree(node, callback):
    """Parcours recursif de l'AST, appelle callback(node) pour chaque noeud."""
    callback(node)
    for child in node.children:
        walk_tree(child, callback)


def find_nodes_by_type(root, node_type: str) -> list:
    """Trouve tous les noeuds d'un type donne dans le sous-arbre."""
    results = []

    def _collect(node):
        if node.type == node_type:
            results.append(node)

    walk_tree(root, _collect)
    return results


def get_enclosing_function(node) -> Optional[object]:
    """Remonte l'arbre pour trouver la function_definition ou method_declaration englobante."""
    current = node.parent
    while current:
        if current.type in ("function_definition", "method_declaration"):
            return current
        current = current.parent
    return None
