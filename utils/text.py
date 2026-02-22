# utils/text.py

def get_node_text(node, source_code):
    return source_code[node.start_byte:node.end_byte].decode('utf-8')
