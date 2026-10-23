"""COBOL paragraphs that no flow of control reaches: the only COBOL dead-code claim.

COBOL files and programs stay exempt (``dead_code_exempt``): a scheduler, a
CICS region definition the repo does not hold, a dynamic ``CALL`` or a web
service can run any program. Inside one program every path is in the text, so
a paragraph is reported when all of these hold:

* its name appears nowhere else in the program or the copybooks it copies, so
  no ``PERFORM``, ``THRU`` bound, ``GO TO``, ``ALTER``, ``SORT`` procedure or
  ``EXEC CICS HANDLE`` names it;
* it is not the first paragraph of the procedure division or of a section;
* the paragraph before it ends in a sentence whose last statement is an
  unconditional ``GOBACK``, ``STOP RUN``, ``GO TO`` or ``EXEC CICS RETURN`` /
  ``XCTL`` (without ``RESP`` or ``NOHANDLE``), so nothing falls through into it;
* the file holds one program, with no ``DECLARATIVES``, ``ENTRY``,
  ``IGNORE CONDITION`` or ``REPLACE``, and every procedure-division ``COPY``
  (and every ``COPY`` inside those, transitively) resolved and free of
  ``REPLACING``.

Any doubt drops the paragraph (recall is the price). A finding is low
confidence and never deletion-ready.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from repowise.core.ingestion.cobol import CopyStatement, code_view, copy_statements

from .constants import _is_fixture_path
from .models import DeadCodeFindingData, DeadCodeKind
from .risk_factors import path_risk_factors

if TYPE_CHECKING:
    import networkx as nx

    from .analyzer import DeadCodeAnalyzer

#: Low tier: below the stored floor, so only a live run with a lower
#: ``--min-confidence`` shows one.
COBOL_PARAGRAPH_CONFIDENCE = 0.3

_PROCEDURE = re.compile(r"\bPROCEDURE\s+DIVISION\b", re.IGNORECASE)
_HEADER = re.compile(
    r"^ {7,10}(?P<name>[A-Z0-9][A-Z0-9-]*)(?P<section>\s+SECTION)?\s*\.[ \t\r]*$",
    re.IGNORECASE | re.MULTILINE,
)
# A verb or scope terminator alone in area A is no paragraph. Only the reserved
# terminators: ``END-PROGRAM.`` is a legal (and common) paragraph name.
_NOT_A_NAME = frozenset(
    {"EXIT", "GOBACK", "CONTINUE"}
    | {
        f"END-{verb}"
        for verb in (
            "ACCEPT", "ADD", "CALL", "COMPUTE", "DELETE", "DISPLAY", "DIVIDE", "EVALUATE",
            "EXEC", "IF", "INVOKE", "JSON", "MULTIPLY", "PERFORM", "READ", "RECEIVE", "RETURN",
            "REWRITE", "SEARCH", "START", "STRING", "SUBTRACT", "UNSTRING", "WRITE", "XML",
        )
    }
)
# ``REPLACE`` rewrites text, so a paragraph can be named by a word no line spells.
_UNSAFE_PROGRAM = re.compile(
    r"\bDECLARATIVES\b|(?<![\w-])ENTRY\s+['\"]|\bIGNORE\s+CONDITION\b|(?<![\w-])REPLACE(?![\w-])",
    re.IGNORECASE,
)
_LITERAL = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"")
_EXEC = re.compile(r"\bEXEC\s+(?:CICS|SQL|SQLIMS|DLI)\b.*?\bEND-EXEC\b", re.IGNORECASE | re.DOTALL)
_SENTENCE_END = re.compile(r"\.(?=\s)")
_TERMINAL = re.compile(
    r"(?:\bGOBACK|\bSTOP RUN|\bGO (?:TO )?[A-Z0-9][A-Z0-9-]*"
    r"|\bEXEC CICS (?:RETURN|XCTL)\b(?:(?!END-EXEC).)*\bEND-EXEC)$"
)
_CONDITIONAL = re.compile(
    r"\bNEXT SENTENCE\b|\bAT END\b|\bINVALID\b|\bSIZE ERROR\b|\bOVERFLOW\b|\bEXCEPTION\b|\bSEARCH\b"
)


def unreachable_paragraphs(code: str, copied: dict[str, str]) -> list[tuple[str, int, int]]:
    """``(name, start line, end line)`` per paragraph of *code* nothing reaches.

    *code* is a program's code view; *copied* maps each member it copies that
    resolved to that member's code view.
    """
    divisions = list(_PROCEDURE.finditer(code))
    if len(divisions) != 1 or _UNSAFE_PROGRAM.search(code):
        return []
    start = divisions[0].end()
    line_of_start = code.count("\n", 0, start) + 1
    copies = [c for c in copy_statements(code) if c.line >= line_of_start]
    if not _closed(copies, copied):
        return []
    lines = code.split("\n")
    headers = [h for h in _HEADER.finditer(code, start) if _is_name(h.group("name"))]
    haystack = "\n".join([code, *copied.values()])
    out: list[tuple[str, int, int]] = []
    for k, header in enumerate(headers):
        if k == 0 or header.group("section") or headers[k - 1].group("section"):
            continue
        name = header.group("name")
        mentions = re.findall(rf"(?<![\w-]){re.escape(name)}(?![\w-])", haystack, re.IGNORECASE)
        if len(mentions) != 1 or not _ends_in_transfer(code[headers[k - 1].end() : header.start()]):
            continue
        first = code.count("\n", 0, header.start()) + 1
        # Up to the next header or the next COPY (a procedure copybook opens its
        # own paragraph), without the blank and comment lines before it.
        last = code.count("\n", 0, headers[k + 1].start()) if k + 1 < len(headers) else None
        last = min([c.line - 1 for c in copies if c.line > first] + [last or code.count("\n") + 1])
        while last > first and not lines[last - 1].strip():
            last -= 1
        out.append((name.upper(), first, last))
    return out


def _is_name(word: str) -> bool:
    """A header word that can name a paragraph: no scope terminator or bare verb."""
    return word.upper() not in _NOT_A_NAME


def _closed(copies: list[CopyStatement], copied: dict[str, str]) -> bool:
    """Whether the code *copies* bring in is all read, transitively, and copied verbatim.

    Every member, and every member those copy in turn, must have resolved, and
    none may use ``REPLACING`` or ``REPLACE``: a rewritten copybook can name a
    paragraph its text never spells.
    """
    pending, seen = list(copies), set()
    while pending:
        statement = pending.pop()
        if statement.replacing or statement.member not in copied:
            return False
        if statement.member in seen:
            continue
        seen.add(statement.member)
        member = copied[statement.member]
        if _UNSAFE_PROGRAM.search(member):
            return False
        pending.extend(copy_statements(member))
    return True


def _ends_in_transfer(body: str) -> bool:
    """Whether *body* (a paragraph) ends in a sentence that always leaves it."""
    text = _LITERAL.sub(lambda m: "X" * len(m.group(0)), body).rstrip()
    if not text.endswith("."):
        return False
    text = text[:-1]
    sentence = " ".join(_SENTENCE_END.split(text)[-1].split()).upper()
    terminal = _TERMINAL.search(sentence)
    if terminal is None or re.search(r"\bRESP2?\b|\bNOHANDLE\b", terminal.group(0)):
        return False
    before = _EXEC.sub(" ", sentence[: terminal.start()])
    if _CONDITIONAL.search(before):
        return False
    return all(
        len(re.findall(rf"(?<![\w-]){opener}(?![\w-])", before))
        == len(re.findall(rf"(?<![\w-])END-{opener}(?![\w-])", before))
        for opener in ("IF", "EVALUATE")
    )


def _copied_closure(graph: nx.DiGraph, path: str) -> set[str]:
    """Every file *path* imports, directly or through the copybooks it copies."""
    found: set[str] = set()
    pending = [path]
    while pending:
        node = pending.pop()
        for dst in graph.successors(node):
            edge = graph.edges[node, dst]
            if edge.get("edge_type") == "imports" and dst not in found and dst != path:
                found.add(dst)
                pending.append(dst)
    return found


def unreachable_paragraph_findings(
    ctx: DeadCodeAnalyzer, whitelist: set[str]
) -> list[DeadCodeFindingData]:
    """An unused-internal finding per COBOL paragraph :func:`unreachable_paragraphs` returns."""
    graph, sources = ctx.graph, ctx._source_map
    findings: list[DeadCodeFindingData] = []
    for path, data in graph.nodes(data=True):
        if data.get("node_type") != "file" or data.get("language") != "cobol":
            continue
        if path not in sources or data.get("is_test") or _is_fixture_path(path):
            continue
        if ctx._should_never_flag(path, whitelist):
            continue
        copied = {
            PurePosixPath(member).stem.upper(): code_view(sources[member])
            for member in _copied_closure(graph, path)
            if member in sources
        }
        for name, start, end in unreachable_paragraphs(code_view(sources[path]), copied):
            findings.append(
                DeadCodeFindingData(
                    kind=DeadCodeKind.UNUSED_INTERNAL,
                    file_path=path,
                    symbol_name=name,
                    symbol_kind="function",
                    confidence=COBOL_PARAGRAPH_CONFIDENCE,
                    reason=f"Paragraph '{name}' is never named and nothing falls through into it",
                    evidence=[
                        f"No statement in the program or its copybooks names '{name}'",
                        "The paragraph before it always transfers control away",
                    ],
                    safe_to_delete=False,
                    risk_factors=list(path_risk_factors(path)),
                    lines=end - start + 1,
                    start_line=start,
                    end_line=end,
                    **ctx._git_fields(path),
                )
            )
    return findings
