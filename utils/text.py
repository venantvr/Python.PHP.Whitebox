# utils/text.py

def get_node_text(node, source_code):
    """Texte d'un noeud tree-sitter (bytes -> str, tolerant aux octets invalides)."""
    return source_code[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
