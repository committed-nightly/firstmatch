"""Ask the real ssh, rather than reimplementing it.

OpenSSH's pattern matcher has negation, a pattern list whose separator depends
on whether you wrote `Host` or `Match host`, and a rule that a list of only
negations matches nothing. Writing a second implementation of that would mean
shipping a tool whose answers are confidently wrong in exactly the cases people
run it for. So `firstmatch` does not match patterns. It builds a two-line
config with a sentinel value, runs `ssh -G`, and reads back which block won.

`ssh -G` is a good oracle: it is about four milliseconds, it needs no network
for ordinary configs, and it is the same binary that will run when you actually
connect.

It has one sharp edge, which is why `requires_exec_consent` exists. `ssh -G`
evaluates `Match exec`, and evaluating it means running the command. Reading a
config you were handed and asking ssh to explain it will execute whatever that
config says. Confirmed on this box: a config containing
`Match exec "touch /tmp/PWNED"` creates the file on `ssh -G`, with no
connection and no prompt. So a config with `Match exec` in it is refused unless
the caller passes --allow-exec.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

HIT = "firstmatch-probe-hit"
MISS = "firstmatch-probe-miss"

# ssh -G on a config with no network access is fast; this is only here so a
# pathological ProxyCommand or KnownHostsCommand cannot hang the tool.
TIMEOUT = 10


class OracleUnavailable(RuntimeError):
    pass


@dataclass
class SshResult:
    ok: bool
    values: dict[str, list[str]]
    stderr: str


def ssh_path() -> str | None:
    return shutil.which("ssh")


def _quote(arg: str) -> str:
    """Put a Match exec command back into the form ssh will re-parse."""
    if any(c in arg for c in ' \t"'):
        return '"' + arg.replace('"', '\\"') + '"'
    return arg


def requires_exec_consent(blocks) -> list:
    """Blocks whose evaluation by ssh would run a command.

    `Match exec` is the only criterion that executes anything during `ssh -G`.
    """
    out = []
    for b in blocks:
        for name, _ in b.criteria:
            if name.lstrip("!") == "exec":
                out.append(b)
                break
    return out


class Oracle:
    def __init__(self, ssh: str | None = None, allow_exec: bool = False) -> None:
        self.ssh = ssh or ssh_path()
        if not self.ssh:
            raise OracleUnavailable(
                "no ssh on PATH. firstmatch asks the real ssh which blocks match, "
                "rather than guessing, so it needs one."
            )
        # When the caller has consented to Match exec, evaluate those blocks for
        # real. Running the command and then refusing to use the answer -- which
        # is what an earlier version of this did -- gets the worst of both.
        self.allow_exec = allow_exec
        self._cache: dict[tuple, bool | None] = {}

    def run(self, config: Path, host: str, extra: list[str] | None = None) -> SshResult:
        cmd = [self.ssh, "-F", str(config), "-G"]
        if extra:
            cmd += extra
        cmd.append(host)
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=TIMEOUT,
                env={**os.environ, "LC_ALL": "C"},
            )
        except subprocess.TimeoutExpired:
            return SshResult(False, {}, f"ssh -G timed out after {TIMEOUT}s")
        values: dict[str, list[str]] = {}
        for line in p.stdout.splitlines():
            parts = line.split(" ", 1)
            if not parts[0]:
                continue
            values.setdefault(parts[0], []).append(parts[1] if len(parts) > 1 else "")
        return SshResult(p.returncode == 0, values, p.stderr.strip())

    def effective(self, config: Path, host: str) -> SshResult:
        """What ssh will actually use for `host`, straight from `ssh -G`."""
        return self.run(config, host)

    def matches(self, block, host: str) -> bool | None:
        """Does `block`'s own header match `host`?

        Returns None when the answer cannot be had without guessing -- a
        criterion whose value depends on how far ssh had got through the file,
        or one that would need a command run.
        """
        key = (block.kind, block.patterns, block.criteria, host)
        if key in self._cache:
            return self._cache[key]
        result = self._matches_uncached(block, host)
        self._cache[key] = result
        return result

    def _matches_uncached(self, block, host: str) -> bool | None:
        if block.kind == "toplevel":
            return True
        if block.kind == "host":
            if not block.patterns:
                return None
            return self._probe(f"Host {' '.join(block.patterns)}", host)

        # Match block. Reduce it to the criteria that can be settled on their
        # own; decline the rest rather than report a guess as a fact.
        probe_parts: list[str] = []
        for name, arg in block.criteria:
            bare = name.lstrip("!")
            negated = name.startswith("!")
            if bare in ("all", "final", "canonical"):
                # `all` always matches. `final` and `canonical` say *when* the
                # block is evaluated, not whether it matches this host; the
                # analyser handles the pass they belong to.
                continue
            if bare in ("host", "originalhost"):
                if arg is None:
                    return None
                probe_parts.append(f"{'!' if negated else ''}{bare} {arg}")
                continue
            if bare == "localuser":
                if arg is None:
                    return None
                probe_parts.append(f"{'!' if negated else ''}localuser {arg}")
                continue
            if bare == "exec":
                if arg is None or not self.allow_exec:
                    return None
                probe_parts.append(f"{'!' if negated else ''}exec {_quote(arg)}")
                continue
            # user and tagged depend on a value an earlier block may have set,
            # so answering would mean assuming the resolution this tool is
            # supposed to be computing.
            return None

        if not probe_parts:
            # Only pass-selecting criteria, e.g. `Match final`. It matches every
            # host; whether its lines win is a different question.
            return True
        return self._probe("Match " + " ".join(probe_parts), host)

    def _probe(self, header: str, host: str) -> bool | None:
        if "\n" in header or "\r" in header:
            return None
        body = f"{header}\n    User {HIT}\nHost *\n    User {MISS}\n"
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "probe"
            cfg.write_text(body, encoding="utf-8")
            res = self.run(cfg, host)
        if not res.ok:
            return None
        got = res.values.get("user", [])
        if got == [HIT]:
            return True
        if got == [MISS]:
            return False
        return None

    def canonicalization_enabled(self, config: Path, host: str) -> bool | None:
        """Is CanonicalizeHostname anything other than `no` for this host?

        `Match canonical` blocks are only ever read on the second pass ssh makes
        after canonicalising the name, and that pass only happens when this is
        on. Asked via `ssh -G` so the default comes from ssh, not from here.
        """
        res = self.run(config, host)
        if not res.ok:
            return None
        vals = res.values.get("canonicalizehostname", [])
        if not vals:
            return None
        return vals[0].strip().lower() not in ("no", "false")
