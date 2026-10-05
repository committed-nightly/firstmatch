"""Read an ssh_config into the block stream ssh itself would walk.

Two things here are less obvious than they look.

`Include` is positional and conditional. An Include inside a Host block is only
read when that block matches, so a file pulled in under `Host work` contributes
nothing when you ssh somewhere else. Every block therefore carries the chain of
blocks it was included under (`guards`), and the analyser ignores a block whose
guards do not all match.

An included file's blocks do not leak past the end of that file. If the include
opens `Host inner` and never closes it, the line after the Include directive in
the *including* file still belongs to whatever block was open there. Verified
against ssh, which is the only reason this file believes it.
"""

from __future__ import annotations

import glob
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path

MAX_INCLUDE_DEPTH = 16


@dataclass(frozen=True)
class Directive:
    key: str  # lowercased keyword
    keyword: str  # as the user spelled it, for display
    args: tuple[str, ...]
    file: Path
    lineno: int
    raw: str

    @property
    def where(self) -> str:
        return f"{self.file}:{self.lineno}"


@dataclass
class Block:
    kind: str  # "toplevel" | "host" | "match"
    patterns: tuple[str, ...] = ()  # host: the whitespace-separated pattern list
    criteria: tuple[tuple[str, str | None], ...] = ()  # match: (keyword, arg)
    directives: list[Directive] = field(default_factory=list)
    file: Path = Path("-")
    lineno: int = 0
    header: str = ""
    guards: tuple[Block, ...] = ()  # blocks this one was conditionally included under
    index: int = 0

    @property
    def where(self) -> str:
        return f"{self.file}:{self.lineno}"

    @property
    def is_final(self) -> bool:
        return any(k == "final" for k, _ in self.criteria)

    @property
    def is_canonical(self) -> bool:
        return any(k == "canonical" for k, _ in self.criteria)

    def criterion(self, name: str) -> str | None:
        for k, v in self.criteria:
            if k == name:
                return v
        return None


@dataclass
class MissingInclude:
    pattern: str
    resolved: str
    file: Path
    lineno: int
    is_glob: bool

    @property
    def where(self) -> str:
        return f"{self.file}:{self.lineno}"


@dataclass
class ParseResult:
    blocks: list[Block]
    missing_includes: list[MissingInclude]
    files: list[Path]


def split_line(line: str) -> tuple[str, list[str]] | None:
    """Split one config line into (keyword, args), or None if it carries nothing.

    ssh accepts `Keyword args`, `Keyword=args` and `Keyword = args`, and allows
    double quotes around arguments.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    # The keyword ends at the first whitespace or '='. Everything after any
    # surrounding '=' and whitespace is the argument text.
    i = 0
    while i < len(stripped) and stripped[i] not in " \t=":
        i += 1
    keyword = stripped[:i]
    rest = stripped[i:].lstrip(" \t")
    if rest.startswith("="):
        rest = rest[1:].lstrip(" \t")
    if not keyword:
        return None

    try:
        args = shlex.split(rest, comments=False)
    except ValueError:
        # Unbalanced quotes. ssh would reject the file; keep the raw text so the
        # caller can still report the line rather than crashing on it.
        args = rest.split()
    return keyword, args


def _default_include_root(path: Path) -> Path:
    """Where ssh resolves a relative Include from.

    Relative includes resolve against ~/.ssh for a user config and /etc/ssh for
    the system one. There is no way to ask ssh which it thinks it is reading, so
    this guesses from the path and prefers ~/.ssh.
    """
    try:
        if Path("/etc/ssh") in path.resolve().parents:
            return Path("/etc/ssh")
    except OSError:
        pass
    return Path.home() / ".ssh"


class _Parser:
    def __init__(self) -> None:
        self.blocks: list[Block] = []
        self.missing: list[MissingInclude] = []
        self.files: list[Path] = []

    def parse_file(
        self,
        path: Path,
        guards: tuple[Block, ...],
        depth: int,
        current: Block | None,
    ) -> Block | None:
        """Parse one file. Returns the block left open at EOF.

        `current` is the block open at the point the file was included. The
        return value is deliberately discarded by the Include handler: a block
        opened inside an included file dies at that file's end.
        """
        if depth > MAX_INCLUDE_DEPTH:
            return current
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return current
        self.files.append(path)

        if current is None:
            current = Block(kind="toplevel", patterns=("*",), file=path, lineno=0, header="(top of file)")
            self._add(current)

        for lineno, line in enumerate(text.splitlines(), start=1):
            parsed = split_line(line)
            if parsed is None:
                continue
            keyword, args = parsed
            key = keyword.lower()

            if key == "host":
                current = Block(
                    kind="host",
                    patterns=tuple(args),
                    file=path,
                    lineno=lineno,
                    header=line.strip(),
                    guards=guards,
                )
                self._add(current)
            elif key == "match":
                current = Block(
                    kind="match",
                    criteria=_parse_match_criteria(args),
                    file=path,
                    lineno=lineno,
                    header=line.strip(),
                    guards=guards,
                )
                self._add(current)
            elif key == "include":
                self._do_include(args, path, lineno, guards, depth, current)
            else:
                current.directives.append(
                    Directive(
                        key=key,
                        keyword=keyword,
                        args=tuple(args),
                        file=path,
                        lineno=lineno,
                        raw=line.strip(),
                    )
                )
        return current

    def _add(self, block: Block) -> None:
        block.index = len(self.blocks)
        self.blocks.append(block)

    def _do_include(
        self,
        args: list[str],
        path: Path,
        lineno: int,
        guards: tuple[Block, ...],
        depth: int,
        current: Block | None,
    ) -> None:
        # An Include sitting inside a Host/Match block is conditional on that
        # block. One at the top of the file is not.
        inner_guards = guards
        if current is not None and current.kind != "toplevel":
            inner_guards = guards + (current,)

        for raw in args:
            expanded = os.path.expanduser(raw)
            if not os.path.isabs(expanded):
                expanded = str(_default_include_root(path) / expanded)
            is_glob = any(c in raw for c in "*?[")
            matches = sorted(glob.glob(expanded))
            if not matches:
                self.missing.append(
                    MissingInclude(
                        pattern=raw,
                        resolved=expanded,
                        file=path,
                        lineno=lineno,
                        is_glob=is_glob,
                    )
                )
                continue
            for m in matches:
                mp = Path(m)
                if mp.is_dir():
                    continue
                # Return value dropped on purpose: see parse_file's docstring.
                self.parse_file(mp, inner_guards, depth + 1, None)
        # After an Include, we are back in the including file's open block. The
        # caller still holds `current`, so there is nothing to restore.


def _parse_match_criteria(args: list[str]) -> tuple[tuple[str, str | None], ...]:
    """Turn `Match` arguments into (criterion, argument-or-None) pairs."""
    from .keywords import MATCH_STANDALONE, MATCH_WITH_ARG

    out: list[tuple[str, str | None]] = []
    i = 0
    while i < len(args):
        name = args[i].lower()
        # `Match !host foo` negates a criterion; keep the bang on the name so
        # the analyser can see it and decline rather than get it backwards.
        bare = name.lstrip("!")
        if bare in MATCH_WITH_ARG and i + 1 < len(args):
            out.append((name, args[i + 1]))
            i += 2
        elif bare in MATCH_STANDALONE:
            out.append((name, None))
            i += 1
        else:
            out.append((name, None))
            i += 1
    return tuple(out)


def parse(path: Path) -> ParseResult:
    p = _Parser()
    p.parse_file(Path(path), (), 0, None)
    # Drop the synthetic top-of-file block if nothing landed in it, so a config
    # that opens with `Host` does not report a phantom block.
    blocks = [b for b in p.blocks if b.kind != "toplevel" or b.directives]
    return ParseResult(blocks=blocks, missing_includes=p.missing, files=p.files)
