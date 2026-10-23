"""CICS CSD resource definitions (DFHCSDUP input): the programs and transactions a region runs.

Read from a ``.csd`` file or from a JCL step's in-stream data. A command
starts on a line whose first word is a DFHCSDUP command and runs until the
next one; a ``*`` in column 1 is a comment. ``DEFINE TRANSACTION(T) ...
PROGRAM(P)`` names the program transaction T runs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ..models import FileInfo, ParsedFile, Symbol

_COMMANDS = frozenset(
    {
        "ADD",
        "ALTER",
        "APPEND",
        "CHECK",
        "COPY",
        "DEFINE",
        "DELETE",
        "EXTRACT",
        "INITIALIZE",
        "LIST",
        "MIGRATE",
        "PROCESS",
        "REMOVE",
        "SCAN",
        "SERVICE",
        "UPGRADE",
        "USERDEFINE",
        "VERIFY",
    }
)
# The command word stands alone: ``DELETE(YES)`` on a continuation line is an attribute.
_COMMAND = re.compile(r"^\s*([A-Z]+)(?=\s|$)", re.IGNORECASE)
_DEFINE = re.compile(
    r"^\s*(?:USER)?DEFINE\s+(?P<resource>[A-Z]+)\s*\(\s*(?P<name>[^()\s]+)\s*\)(?P<rest>.*)",
    re.IGNORECASE | re.DOTALL,
)
_PROGRAM = re.compile(r"(?<![\w-])PROGRAM\s*\(\s*(?P<name>[^()\s]+)\s*\)", re.IGNORECASE)


@dataclass(frozen=True)
class CsdDefinition:
    """One ``DEFINE``: its resource type and name, and a transaction's program."""

    resource: str
    name: str
    line: int
    program: str | None = None


def read_csd(lines: Iterable[tuple[int, str]]) -> list[CsdDefinition]:
    """Every ``DEFINE`` in *lines* (``(line number, text)``), continuation lines joined."""
    commands: list[tuple[int, str]] = []
    for number, line in lines:
        if line.startswith("*") or not line.strip():
            continue
        word = _COMMAND.match(line)
        if word and word.group(1).upper() in _COMMANDS:
            commands.append((number, line))
        elif commands:
            commands[-1] = (commands[-1][0], f"{commands[-1][1]} {line}")
    out: list[CsdDefinition] = []
    for number, text in commands:
        m = _DEFINE.match(text)
        if m is None:
            continue
        resource = m.group("resource").upper()
        program = _PROGRAM.search(m.group("rest")) if resource == "TRANSACTION" else None
        out.append(
            CsdDefinition(
                resource,
                m.group("name").upper(),
                number,
                program.group("name").upper() if program else None,
            )
        )
    return out


def defined_programs(definitions: list[CsdDefinition]) -> list[str]:
    """The programs *definitions* make runnable: each PROGRAM, and each transaction's program."""
    names = {d.name for d in definitions if d.resource == "PROGRAM"}
    names |= {d.program for d in definitions if d.program}
    return sorted(names)


def parse_csd_file(file_info: FileInfo, source: bytes) -> ParsedFile:
    """Each defined resource as a symbol: ``TRANSACTION CAUP PROGRAM(COACTUPC)``."""
    lines = source.decode("utf-8", errors="replace").splitlines()
    definitions = read_csd(enumerate(lines, 1))
    symbols = [
        Symbol(
            id=f"{file_info.path}::{d.resource}:{d.name}",
            name=d.name,
            qualified_name=f"{d.resource}:{d.name}",
            kind="variable",
            signature=f"{d.resource} {d.name}" + (f" PROGRAM({d.program})" if d.program else ""),
            start_line=d.line,
            end_line=next_line - 1,
            docstring=None,
            language="csd",
        )
        for d, next_line in zip(
            definitions,
            [d.line for d in definitions[1:]] + [len(lines) + 1],
            strict=True,
        )
    ]
    return ParsedFile(
        file_info=file_info,
        symbols=symbols,
        imports=[],
        exports=[s.name for s in symbols],
        docstring=None,
        parse_errors=[],
    )
