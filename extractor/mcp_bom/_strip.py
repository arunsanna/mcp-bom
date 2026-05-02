"""Comment/string masking for regex-based detectors.

Goal: when a detector grep's for a keyword like 'Client' or '.listen(', it
should NOT match inside comments or string literals. AST-based paths already
handle this; this module is for the regex paths that do not parse the source.

The implementation is deliberately heuristic — it strips whole comment blocks
but does not try to be perfect about pathological cases. This is good enough
to remove the obvious false positives ('Client' in a docstring,
'.listen()' in an example comment) without introducing new failure modes.
"""
from __future__ import annotations

import re

_PY_BLOCK_DOCSTRING = re.compile(r'("""|\'\'\').*?\1', re.DOTALL)
_PY_LINE_COMMENT = re.compile(r"#[^\n]*")
_PY_STRING = re.compile(r'(?<!\\)(?:"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\')')

_C_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_C_LINE_COMMENT = re.compile(r"//[^\n]*")
_C_STRING = re.compile(r'(?<!\\)(?:"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`(?:[^`\\]|\\.)*`)', re.DOTALL)


def strip_comments_and_strings(content: str, language: str) -> str:
    """Replace comment and string-literal regions with whitespace of equal
    length so positions in the original are preserved.
    """
    def _blank(m: re.Match) -> str:
        return " " * (m.end() - m.start())

    if language == "python":
        content = _PY_BLOCK_DOCSTRING.sub(_blank, content)
        content = _PY_LINE_COMMENT.sub(_blank, content)
        content = _PY_STRING.sub(_blank, content)
    elif language in ("typescript", "javascript", "go"):
        content = _C_BLOCK_COMMENT.sub(_blank, content)
        content = _C_LINE_COMMENT.sub(_blank, content)
        content = _C_STRING.sub(_blank, content)
    return content


def language_for_path(path: str) -> str:
    if path.endswith(".py"):
        return "python"
    if path.endswith((".ts", ".tsx", ".js", ".jsx")):
        return "typescript"
    if path.endswith(".go"):
        return "go"
    return "unknown"
