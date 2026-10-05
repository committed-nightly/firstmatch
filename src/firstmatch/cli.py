"""Command line. Two questions: what is dead, and what won."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import analyse, report
from .oracle import Oracle, OracleUnavailable, requires_exec_consent
from .parse import parse

DEFAULT_CONFIG = Path.home() / ".ssh" / "config"

EXEC_REFUSAL = """\
{where}: this config contains `Match exec`, and firstmatch will not run it.

firstmatch answers by invoking `ssh -G`, and `ssh -G` evaluates Match exec --
which means running the command, with no connection and no prompt. On a config
you wrote that is fine. On one you were handed it is arbitrary code execution
dressed as a lint.

If this config is yours and you want it evaluated, pass --allow-exec.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="firstmatch",
        description="Find the ssh_config lines that never apply, and say which line won.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "-F",
            "--config",
            type=Path,
            default=None,
            help=f"config to read (default: {DEFAULT_CONFIG})",
        )
        sp.add_argument(
            "--allow-exec",
            action="store_true",
            help="permit evaluation of a config containing `Match exec`, which runs commands",
        )
        sp.add_argument("--json", action="store_true", help="machine-readable output")

    c = sub.add_parser("check", help="report lines that never apply")
    common(c)
    c.add_argument(
        "--host",
        action="append",
        dest="hosts",
        help="check this host instead of the names found in the config (repeatable)",
    )
    c.add_argument(
        "-q", "--quiet", action="store_true", help="one line per finding, no explanations"
    )

    e = sub.add_parser("explain", help="show the effective config for one host, with provenance")
    common(e)
    e.add_argument("host")
    e.add_argument(
        "--all",
        action="store_true",
        help="include keywords this config never sets, with ssh's defaults",
    )

    return p


def _resolve_config(arg: Path | None) -> Path:
    path = arg or DEFAULT_CONFIG
    if not path.exists():
        if arg is None:
            raise SystemExit(
                f"firstmatch: no config at {path}. Pass -F to point at one."
            )
        raise SystemExit(f"firstmatch: {path}: no such file")
    if path.is_dir():
        raise SystemExit(f"firstmatch: {path} is a directory")
    return path


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = _resolve_config(args.config)

    parsed = parse(config)

    exec_blocks = requires_exec_consent(parsed.blocks)
    if exec_blocks and not args.allow_exec:
        print(EXEC_REFUSAL.format(where=exec_blocks[0].where), file=sys.stderr)
        return 2

    try:
        oracle = Oracle(allow_exec=args.allow_exec)
    except OracleUnavailable as exc:
        print(f"firstmatch: {exc}", file=sys.stderr)
        return 2

    if args.command == "explain":
        res = analyse.resolve(parsed, args.host, config, oracle)
        sc = analyse.self_check(res, config, oracle)
        if args.json:
            print(report.to_json([], [res], parsed.files, sc))
        else:
            sys.stdout.write(report.format_explain(res, config, oracle, args.all))
        _warn_self_check(sc)
        return 3 if (not sc.ok and not sc.declined) else 0

    findings, resolutions = analyse.check(parsed, config, oracle, args.hosts)
    sc = analyse.SelfCheck(declined=False, problems=[])
    if resolutions:
        sc = analyse.self_check(resolutions[0], config, oracle)

    if args.json:
        print(report.to_json(findings, resolutions, parsed.files, sc))
    else:
        text = report.format_findings(findings, verbose=not args.quiet)
        if text:
            sys.stdout.write(text)
        if not args.quiet:
            sys.stdout.write(
                report.summarise(findings, [r.host for r in resolutions], parsed.files)
            )
    _warn_self_check(sc)
    if not sc.ok and not sc.declined:
        return 3
    return 1 if findings else 0


def _warn_self_check(sc) -> None:
    """Say which kind of uncertainty this is, because they mean different things."""
    if sc.ok:
        return
    if sc.declined:
        header = "\nsome of this config was not evaluated, so the values above are incomplete:"
    else:
        header = (
            "\nfirstmatch disagrees with ssh -G, which means firstmatch is wrong here.\n"
            "Please report this with the config that caused it:"
        )
    print(header, file=sys.stderr)
    for p in sc.problems:
        print(f"  {p}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
