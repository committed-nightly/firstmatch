"""Work out which line won, and which lines never could.

The rule is one sentence: for most keywords ssh keeps the value from the first
matching block and ignores every later one. Everything below is consequences of
that sentence, and all of them bite in the same direction -- the general block
at the top of your file quietly beats the specific block at the bottom, which is
the opposite of how every other configuration format you use behaves.

Two consequences are worth naming because they do not look like ordering bugs
at all:

`Match final` loses to everything. ssh reads final blocks on a second pass over
the file, after the first pass is done. First-wins still applies on that pass,
so a `Match final` block can only ever set a keyword that no ordinary block set
-- regardless of where in the file it sits. A `Match final` at the very top of
the file still loses to a `Host *` at the very bottom. The word "final" means
"last to speak", and under first-wins, last means loses.

`Host a,b` matches nothing. Host pattern lists are separated by whitespace, so
the commas are part of a single literal pattern. `Match host a,b` *is*
comma-separated, which is where the habit comes from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .keywords import accumulates
from .oracle import Oracle
from .parse import Block, Directive, ParseResult

WILDCARD_CHARS = "*?"

# A hostname no sane config names explicitly, used to represent "some host you
# did not list". Needed so a catch-all block can be seen winning something.
CATCHALL_PROBE = "firstmatch-any-host"


@dataclass
class Assignment:
    directive: Directive
    block: Block
    state: str  # live | accumulated | shadowed | dead-final | dead-canonical
    winner: Directive | None = None
    winner_block: Block | None = None
    note: str = ""


@dataclass
class Resolution:
    host: str
    assignments: list[Assignment] = field(default_factory=list)
    winners: dict[str, Directive] = field(default_factory=dict)
    winner_blocks: dict[str, Block] = field(default_factory=dict)
    predicted: dict[str, list[str]] = field(default_factory=dict)
    unevaluated: list[Block] = field(default_factory=list)
    matched_blocks: list[Block] = field(default_factory=list)

    def shadowed(self) -> list[Assignment]:
        return [a for a in self.assignments if a.state in ("shadowed", "dead-final")]


@dataclass
class Finding:
    code: str
    where: str
    message: str
    detail: str = ""
    hosts: tuple[str, ...] = ()
    certainty: str = "always"  # always | probed

    def as_dict(self) -> dict:
        d = {
            "code": self.code,
            "where": self.where,
            "message": self.message,
            "certainty": self.certainty,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.hosts:
            d["hosts"] = list(self.hosts)
        return d


def _block_applies(block: Block, host: str, oracle: Oracle) -> bool | None:
    """Does this block contribute to `host`, guards included?

    A block pulled in by an Include that sits inside a non-matching Host block
    was never read at all, so its guards have to match too.
    """
    for guard in block.guards:
        g = oracle.matches(guard, host)
        if g is not True:
            return g  # False or None propagates
    return oracle.matches(block, host)


def resolve(parsed: ParseResult, host: str, config: Path, oracle: Oracle) -> Resolution:
    """Replay ssh's walk over the config for one host, keeping provenance."""
    res = Resolution(host=host)
    canon = oracle.canonicalization_enabled(config, host)

    applicable: list[Block] = []
    for block in parsed.blocks:
        state = _block_applies(block, host, oracle)
        if state is None:
            res.unevaluated.append(block)
            continue
        if not state:
            continue
        applicable.append(block)
        res.matched_blocks.append(block)

    # ssh makes the ordinary pass first, then -- only if canonicalisation is on
    # -- a canonicalising pass, then the final pass. Canonical blocks are only
    # ever read on that middle pass.
    first_pass = [b for b in applicable if not b.is_final and not b.is_canonical]
    canonical_pass = [b for b in applicable if b.is_canonical and not b.is_final]
    final_pass = [b for b in applicable if b.is_final]

    def consume(blocks: list[Block], pass_name: str) -> None:
        for block in blocks:
            for d in block.directives:
                if accumulates(d.key):
                    res.predicted.setdefault(d.key, []).append(" ".join(d.args))
                    res.assignments.append(
                        Assignment(d, block, "accumulated", note=f"{d.keyword} adds rather than replaces")
                    )
                    continue
                prior = res.winners.get(d.key)
                if prior is None:
                    res.winners[d.key] = d
                    res.winner_blocks[d.key] = block
                    res.predicted[d.key] = [" ".join(d.args)]
                    res.assignments.append(Assignment(d, block, "live"))
                else:
                    state = "dead-final" if pass_name == "final" else "shadowed"
                    res.assignments.append(
                        Assignment(
                            d,
                            block,
                            state,
                            winner=prior,
                            winner_block=res.winner_blocks.get(d.key),
                        )
                    )

    consume(first_pass, "first")
    if canon is True:
        consume(canonical_pass, "canonical")
    else:
        for block in canonical_pass:
            for d in block.directives:
                res.assignments.append(
                    Assignment(
                        d,
                        block,
                        "dead-canonical",
                        note="CanonicalizeHostname is no, so the canonicalising pass never runs",
                    )
                )
    consume(final_pass, "final")
    return res


# ---------------------------------------------------------------------------
# config-wide checks, which need no host


def _negation_only(patterns: tuple[str, ...]) -> bool:
    return bool(patterns) and all(p.startswith("!") for p in patterns)


def static_findings(parsed: ParseResult) -> list[Finding]:
    findings: list[Finding] = []

    for mi in parsed.missing_includes:
        if mi.is_glob:
            msg = f"Include {mi.pattern} matches no file"
            detail = (
                f"expanded to {mi.resolved}, which matched nothing. ssh does not "
                "mention this; the directive is simply skipped."
            )
        else:
            msg = f"Include {mi.pattern} does not exist"
            detail = (
                f"resolved to {mi.resolved}, which is not there. A missing non-glob "
                "Include is silent too -- ssh exits 0 and carries on, so a typo in "
                "the path costs you the whole file with no warning."
            )
        findings.append(Finding("include-missing", mi.where, msg, detail))

    for b in parsed.blocks:
        if b.kind == "host":
            commas = [p for p in b.patterns if "," in p]
            if commas:
                findings.append(
                    Finding(
                        "comma-in-host",
                        b.where,
                        f"Host pattern {commas[0]!r} contains a comma and matches nothing",
                        "Host pattern lists are separated by whitespace, so the commas are "
                        "part of the pattern. Write `Host "
                        + " ".join(commas[0].split(","))
                        + "`. (`Match host` really is comma-separated, which is where this "
                        "habit comes from.)",
                    )
                )
            if _negation_only(b.patterns):
                findings.append(
                    Finding(
                        "never-matches",
                        b.where,
                        f"Host {' '.join(b.patterns)} matches no host at all",
                        "A pattern list of only negations never matches: ssh needs a "
                        "positive pattern to match first before a negation can exclude "
                        "anything. Add `*` to the list to mean 'everything except these'.",
                    )
                )
        if b.kind == "match":
            for name, arg in b.criteria:
                if name.lstrip("!") in ("host", "originalhost") and arg:
                    pats = tuple(arg.split(","))
                    if _negation_only(pats):
                        findings.append(
                            Finding(
                                "never-matches",
                                b.where,
                                f"Match {name} {arg} matches no host at all",
                                "A pattern list of only negations never matches.",
                            )
                        )
    return findings


def probe_hosts(parsed: ParseResult, limit: int = 40) -> list[str]:
    """Hosts worth testing, taken from the config's own names.

    Literal names first, because they are the ones the author cared about. Then
    one synthetic name per wildcard pattern, so a config made entirely of
    wildcards still gets checked.
    """
    literals: list[str] = []
    synthetic: list[str] = []

    def consider(pattern: str) -> None:
        if pattern.startswith("!") or "," in pattern:
            return
        if any(c in pattern for c in WILDCARD_CHARS):
            if pattern == "*":
                return  # matches the others; adds nothing
            fake = pattern.replace("*", "wild").replace("?", "x")
            if fake and fake not in synthetic:
                synthetic.append(fake)
        elif pattern not in literals:
            literals.append(pattern)

    for b in parsed.blocks:
        if b.kind == "host":
            for p in b.patterns:
                consider(p)
        elif b.kind == "match":
            for name, arg in b.criteria:
                if name.lstrip("!") in ("host", "originalhost") and arg:
                    for p in arg.split(","):
                        consider(p)

    # Always probe a name that matches nothing specific. Without it, a trailing
    # `Host *` block looks dead: it loses to every named host in the file, and
    # the one host it wins for -- anything not named -- would never be tested.
    # Flagging that block would be flagging the correct idiom.
    hosts = literals + synthetic
    hosts = hosts[: max(limit - 1, 1)]
    if CATCHALL_PROBE not in hosts:
        hosts.append(CATCHALL_PROBE)
    return hosts


def _shadow_advice(a: Assignment, w: Directive) -> str:
    """The fix, which is a different fix depending on where the winner is.

    Telling someone to reorder their blocks is useless when both lines are in
    the same block, and that case is common for SetEnv -- which looks additive,
    reads additive, and is not.
    """
    kw = a.directive.keyword
    same_block = a.winner_block is not None and a.winner_block is a.block
    if same_block:
        base = (
            f"Both lines are in the same block. {kw} keeps only its first value, so "
            f"the one at {w.where} is the one that applies and this one is dead."
        )
        if a.directive.key == "setenv":
            return (
                base + " SetEnv does not accumulate -- not across blocks and not even "
                "across two lines of one block, which is the opposite of SendEnv right "
                "next to it in the man page. To set both, put them on one line: "
                "`SetEnv " + " ".join([" ".join(w.args), " ".join(a.directive.args)]) + "`."
            )
        return base + f" If you need both values, {kw} cannot express that."
    return (
        f"ssh keeps the first {kw} it finds. {w.where} matches too and comes first, "
        "so this line is dead. Move the general block below the specific one, or "
        "delete this line."
    )


def _always_shadows(winner_block: Block) -> bool:
    """True if this block beats a later one for every host, not just the probes."""
    if winner_block.guards:
        return False
    if winner_block.kind == "toplevel":
        return True
    return winner_block.kind == "host" and winner_block.patterns == ("*",)


def check(
    parsed: ParseResult, config: Path, oracle: Oracle, hosts: list[str] | None = None
) -> tuple[list[Finding], list[Resolution]]:
    findings = static_findings(parsed)
    hosts = hosts or probe_hosts(parsed)
    resolutions = [resolve(parsed, h, config, oracle) for h in hosts]

    # A line is only dead if it never wins. `Host *` at the bottom of the file
    # loses to every named host above it and wins for everything else, which is
    # the recommended layout -- so a line that is live for any probed host is
    # not reported at all.
    ever_live: set[tuple[str, int, str]] = set()
    for r in resolutions:
        for a in r.assignments:
            if a.state in ("live", "accumulated"):
                ever_live.add((str(a.directive.file), a.directive.lineno, a.directive.key))

    # Group the remainder by the losing line, so a keyword dead for twelve hosts
    # is one finding naming twelve hosts rather than twelve findings.
    grouped: dict[tuple[str, int, str], dict] = {}
    for r in resolutions:
        for a in r.shadowed():
            k = (str(a.directive.file), a.directive.lineno, a.directive.key)
            if k in ever_live:
                continue
            e = grouped.setdefault(k, {"a": a, "hosts": [], "always": False})
            e["hosts"].append(r.host)
            if a.winner_block is not None and _always_shadows(a.winner_block):
                e["always"] = True

    for e in grouped.values():
        a: Assignment = e["a"]
        w = a.winner
        assert w is not None
        if a.state == "dead-final":
            findings.append(
                Finding(
                    "final-loses",
                    a.directive.where,
                    f"{a.directive.keyword} in a `Match final` block never applies",
                    f"{w.keyword} was already set at {w.where}. Final blocks are read on a "
                    "second pass after the whole file, and first-wins still applies there, "
                    "so a final block can only set a keyword nothing else set. Moving it "
                    "earlier in the file will not help.",
                    hosts=tuple(e["hosts"]),
                    certainty="always" if e["always"] else "probed",
                )
            )
        else:
            findings.append(
                Finding(
                    "shadowed",
                    a.directive.where,
                    f"{a.directive.keyword} never applies; {w.where} already set it",
                    _shadow_advice(a, w),
                    hosts=tuple(e["hosts"]),
                    certainty="always" if e["always"] else "probed",
                )
            )

    for r in resolutions[:1]:
        for a in r.assignments:
            if a.state == "dead-canonical":
                findings.append(
                    Finding(
                        "canonical-never",
                        a.directive.where,
                        f"{a.directive.keyword} in a `Match canonical` block never applies",
                        "CanonicalizeHostname is no, which is the default, so ssh never makes "
                        "the canonicalising pass and never reads this block. Set "
                        "CanonicalizeHostname to yes or always, or drop the block.",
                    )
                )

    order = {
        "shadowed": 0,
        "final-loses": 1,
        "canonical-never": 2,
        "never-matches": 3,
        "comma-in-host": 4,
        "include-missing": 5,
    }
    findings.sort(key=lambda f: (order.get(f.code, 9), f.where))
    return findings, resolutions


@dataclass
class SelfCheck:
    """Whether the attribution agrees with ssh.

    `declined` separates "we chose not to evaluate part of this config" from
    "we evaluated it and got a different answer than ssh". Only the second is a
    reason to distrust the output.
    """

    declined: bool
    problems: list[str]

    @property
    def ok(self) -> bool:
        return not self.problems


# `ssh -G` prints a normalised rendering, not the text you wrote, so a plain
# string compare reports differences that are not disagreements. Observed on
# OpenSSH 9.6: `LogLevel DEBUG1` prints as `DEBUG`, `LocalForward 7001 h:22`
# prints as `7001 [h]:22`, `IPQoS af11` prints as `af11 af11`, and
# `CanonicalizeHostname yes` prints as `true` while `Compression yes` stays
# `yes`. For these the value is not comparable, so the self-check compares only
# how many values there are.
REWRITTEN_BY_SSH = frozenset(
    {
        "channeltimeout",
        "dynamicforward",
        "ipqos",
        "localforward",
        "loglevel",
        "permitremoteopen",
        "remoteforward",
        "rekeylimit",
    }
)

_BOOL_TRUE = {"yes", "true"}
_BOOL_FALSE = {"no", "false"}


def _comparable(key: str, written: str) -> str | None:
    """Normalise a written value for comparison, or None if it cannot be compared."""
    if key in REWRITTEN_BY_SSH:
        return None
    v = written.strip()
    if "%" in v:
        return None  # %h, %p and friends are expanded by the time -G prints them
    if v[:1] in ("+", "-", "^"):
        return None  # list modifiers expand against ssh's built-in default list
    low = v.lower()
    if low in _BOOL_TRUE:
        return "<true>"
    if low in _BOOL_FALSE:
        return "<false>"
    # Our parse removes the quotes around an argument; ssh -G echoes them back
    # as written. `"/bin/cmd with space" -x` and `/bin/cmd with space -x` are
    # the same command, so quotes come off both sides before comparing.
    return v.replace('"', "")


def self_check(res: Resolution, config: Path, oracle: Oracle) -> SelfCheck:
    """Compare what this tool predicted against what ssh -G actually says.

    This exists because the whole value of the tool is the attribution, and the
    attribution is the one part ssh cannot confirm directly. If the value we say
    a line produced is not the value ssh ends up with, we picked the wrong line.

    It deliberately errs towards silence. A spurious "firstmatch is wrong"
    teaches people to ignore output that is usually right, which is worse than
    missing a disagreement -- so anything whose rendering cannot be compared is
    skipped, and a config containing blocks we declined to evaluate reports that
    rather than claiming a bug.
    """
    truth = oracle.effective(config, res.host)
    if not truth.ok:
        return SelfCheck(declined=False, problems=[f"ssh -G failed for {res.host}: {truth.stderr}"])

    problems = []
    for key, predicted in res.predicted.items():
        actual = truth.values.get(key)
        if actual is None:
            continue
        if len(predicted) == 1 and len(actual) == 1:
            mine = _comparable(key, predicted[0])
            if mine is None:
                continue
            theirs = _comparable(key, actual[0])
            if theirs is not None and mine != theirs:
                problems.append(
                    f"{key}: firstmatch predicted {predicted[0]!r}, ssh -G says {actual[0]!r}"
                )
        elif len(predicted) != len(actual) and key not in REWRITTEN_BY_SSH:
            problems.append(
                f"{key}: firstmatch predicted {len(predicted)} value(s), ssh -G has {len(actual)}"
            )

    if problems and res.unevaluated:
        # We told the user we were not going to evaluate these. A difference is
        # the expected consequence of that, not a defect.
        headers = ", ".join(b.where for b in res.unevaluated[:3])
        return SelfCheck(
            declined=True,
            problems=[
                f"{len(res.unevaluated)} block(s) were not evaluated ({headers}), so "
                "these values are incomplete rather than wrong: " + "; ".join(problems)
            ],
        )
    return SelfCheck(declined=False, problems=problems)
