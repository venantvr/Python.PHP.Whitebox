# parser/php_parser.py - Tree-sitter PHP parser with encoding resilience

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Union

import tree_sitter_php as tspython
from tree_sitter import Language, Parser

logger = logging.getLogger(__name__)

PHP_LANGUAGE = Language(tspython.language_php())

# Module-level singleton parser instance.  Thread-safe for *reads* in CPython
# because of the GIL, but each worker process should call ``get_parser()``
# to obtain its own instance when using multiprocessing.
_parser = Parser(PHP_LANGUAGE)


def get_parser() -> Parser:
    """Return a new ``Parser`` instance bound to the PHP language.

    Use this in multiprocessing workers so that each process owns its own
    parser object rather than sharing the module-level singleton across a
    ``fork()`` boundary.
    """
    p = Parser(PHP_LANGUAGE)
    return p


def _read_file_with_fallback(file_path: Union[str, Path]) -> str:
    """Read a file trying multiple encodings to maximise resilience.

    Attempt order:
    1. UTF-8 (strict) -- the vast majority of modern PHP files.
    2. Latin-1 (ISO 8859-1) -- legacy Western-European PHP code.
    3. UTF-8 with replacement characters -- guaranteed to succeed.

    Returns the file content as a Python *str*.
    """
    path = Path(file_path)
    raw_bytes = path.read_bytes()

    # 1. Try strict UTF-8
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        pass

    # 2. Try Latin-1 (never raises, but we keep the explicit step for
    #    clarity and to log the fallback).
    try:
        text = raw_bytes.decode("latin-1")
        logger.debug("File %s decoded as latin-1 (not valid UTF-8)", file_path)
        return text
    except UnicodeDecodeError:
        pass  # pragma: no cover -- latin-1 accepts all byte values

    # 3. Last resort: UTF-8 with replacement characters.
    text = raw_bytes.decode("utf-8", errors="replace")
    logger.warning(
        "File %s contained invalid bytes; decoded with replacement characters",
        file_path,
    )
    return text


def parse_php_file(
    file_path: Union[str, Path],
    parser_instance: Optional[Parser] = None,
) -> tuple:
    """Parse a PHP file and return its tree-sitter AST together with the source.

    Parameters
    ----------
    file_path:
        Path to the ``.php`` file to parse.
    parser_instance:
        Optional ``Parser`` to use.  When *None* the module-level singleton
        is used.  Pass a dedicated parser when calling from a worker process
        (see ``get_parser()``).

    Returns
    -------
    tuple[tree_sitter.Tree, str]
        A ``(tree, source_code)`` pair where *source_code* is the file
        content as a Python *str* and *tree* is the parsed tree-sitter AST.

    Raises
    ------
    FileNotFoundError
        If *file_path* does not exist.
    IsADirectoryError
        If *file_path* points to a directory.
    """
    p = parser_instance if parser_instance is not None else _parser
    code = _read_file_with_fallback(file_path)
    tree = p.parse(code.encode("utf-8"))
    return tree, code
