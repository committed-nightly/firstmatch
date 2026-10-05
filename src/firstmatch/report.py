"""Output. Grep-friendly by default, because that is how a linter gets used."""

from __future__ import annotations

import json
from pathlib import Path

from .analyse import Finding, Resolution
from .oracle import Oracle

CERTAINTY_NOTE = {
    "always": "",
    "probed": " (for the hosts named in this config)",
}


def format_findings(findings: list[Finding], verbose: bool) -> str:
    if not findings:
        return ""
    out = []
    for f in findings:
        out.append(f"{f.where}: {f.code}: {f.message}{CERTAINTY_NOTE.get(f.certainty, '')}")
        if verbose and f.detail:
            for line in _wrap(f.detail, 76):
                out.append(f"    {line}")
            if f.hosts:
                shown = ", ".join(f.hosts[:6])
                more = f" and {len(f.hosts) - 6} more" if len(f.hosts) > 6 else ""
                out.append(f"    hosts: {shown}{more}")
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def summarise(findings: list[Finding], hosts: list[str], files: list[Path]) -> str:
    if not findings:
        return (
            f"no dead lines. {len(files)} file(s), {len(hosts)} host name(s) checked.\n"
        )
    by_code: dict[str, int] = {}
    for f in findings:
        by_code[f.code] = by_code.get(f.code, 0) + 1
    parts = ", ".join(f"{v} {k}" for k, v in sorted(by_code.items()))
    return f"\n{len(findings)} finding(s): {parts}. {len(hosts)} host name(s) checked.\n"


def format_explain(
    res: Resolution,
    config: Path,
    oracle: Oracle,
    show_all: bool,
) -> str:
    truth = oracle.effective(config, res.host)
    out = [f"ssh {res.host}   effective configuration, and the line that set it", ""]

    # Group the live/accumulated assignments by keyword, in the order ssh prints
    # them so the output can be diffed against `ssh -G`.
    set_keys = sorted(res.predicted)
    keys = sorted(truth.values) if show_all else set_keys

    width = max([len(k) for k in keys] + [8])
    for key in keys:
        actual = truth.values.get(key, [])
        sources = [
            a for a in res.assignments if a.directive.key == key and a.state in ("live", "accumulated")
        ]
        if not actual and not sources:
            continue
        shown = actual or [" ".join(a.directive.args) for a in sources]
        for i, val in enumerate(shown):
            src = ""
            if i < len(sources):
                src = sources[i].directive.where
            elif not sources:
                src = "(ssh default)"
            label = key if i == 0 else ""
            out.append(f"  {label:<{width}}  {val:<34}  {src}")

    dead = res.shadowed() + [a for a in res.assignments if a.state == "dead-canonical"]
    if dead:
        out.append("")
        out.append(f"{len(dead)} line(s) in this config will not be used for {res.host}:")
        for a in dead:
            if a.winner is not None:
                why = f"lost to {a.winner.where}"
                if a.state == "dead-final":
                    why += " (final blocks are read last, and last loses)"
            else:
                why = a.note
            out.append(f"  {a.directive.where:<22} {a.directive.raw:<36} {why}")

    if res.unevaluated:
        out.append("")
        out.append("not evaluated, because the answer would be a guess:")
        for b in res.unevaluated:
            out.append(f"  {b.where:<22} {b.header}")

    return "\n".join(out) + "\n"


def to_json(
    findings: list[Finding],
    resolutions: list[Resolution],
    files: list[Path],
    self_check,
) -> str:
    return json.dumps(
        {
            "findings": [f.as_dict() for f in findings],
            "hosts_checked": [r.host for r in resolutions],
            "files_read": [str(p) for p in files],
            "unevaluated_blocks": [
                {"where": b.where, "header": b.header}
                for r in resolutions
                for b in r.unevaluated
            ],
            "self_check": {
                "ok": self_check.ok,
                "declined": self_check.declined,
                "problems": self_check.problems,
            },
        },
        indent=2,
    )


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines
