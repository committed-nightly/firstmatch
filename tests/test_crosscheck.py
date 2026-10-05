"""Check our attribution against `ssh -G` on a battery of configs.

Everything else in the suite tests that firstmatch reports what we think it
should. This tests the only thing that really matters: that the value we claim a
line produced is the value ssh actually ends up with. If those drift apart, the
line numbers in the output are fiction, and that is the whole product.

`ssh -G` cannot confirm the attribution directly -- it never says which line won
-- so this is the closest available thing: predict every value, then ask.
"""

from __future__ import annotations

import pytest

from firstmatch import analyse
from firstmatch.parse import parse

from .conftest import needs_ssh

CONFIGS = {
    "general-block-first": """
        Host *
            User deploy
            IdentityFile ~/.ssh/id_default
            ServerAliveInterval 30
        Host github.com
            User git
            Port 443
            IdentityFile ~/.ssh/id_github
    """,
    "general-block-last": """
        Host github.com
            User git
            Port 443
        Host *.internal
            User admin
        Host *
            User deploy
            ServerAliveInterval 30
    """,
    "nested-wildcards": """
        Host *.example.com
            User alpha
        Host web*.example.com
            User beta
            Port 2222
        Host *
            Compression yes
    """,
    "negations": """
        Host * !legacy.example
            User modern
        Host legacy.example
            User ancient
    """,
    "final-and-ordinary": """
        Match final host prod
            User finaluser
            Port 2022
        Host prod
            User realuser
    """,
    "canonical-off": """
        Match canonical host prod
            Port 2200
        Host prod
            User u
    """,
    "canonical-on": """
        CanonicalizeHostname yes
        CanonicalDomains example.com
        Host prod
            User u
        Host *
            Port 22
    """,
    "toplevel-directives": """
        Compression yes
        User globaluser
        Host github.com
            User git
    """,
    "accumulating-keywords": """
        Host *
            IdentityFile ~/.ssh/id_a
            SendEnv AAA
        Host gh
            IdentityFile ~/.ssh/id_b
            SendEnv BBB
            CertificateFile ~/.ssh/cert_b
    """,
    "equals-and-quotes": """
        Host=quoted
            User=bob
            ProxyCommand "/bin/echo with space" -x
    """,
    "many-keywords": """
        Host target
            User u
            Port 2022
            Compression yes
            ServerAliveInterval 15
            ServerAliveCountMax 3
            StrictHostKeyChecking no
            ConnectTimeout 7
            AddKeysToAgent yes
            ForwardAgent yes
        Host *
            User fallback
            Port 22
    """,
}

HOSTS = [
    "github.com",
    "prod",
    "gh",
    "target",
    "quoted",
    "legacy.example",
    "web1.example.com",
    "other.example.com",
    "host.internal",
    "firstmatch-any-host",
]


def _dedent(text: str) -> str:
    return "\n".join(line.strip() for line in text.strip().splitlines()) + "\n"


@needs_ssh
@pytest.mark.parametrize("name", sorted(CONFIGS))
@pytest.mark.parametrize("host", HOSTS)
def test_predicted_values_match_ssh_g(write_config, oracle, name, host):
    cfg = write_config(_dedent(CONFIGS[name]), name=f"{name}.config")
    res = analyse.resolve(parse(cfg), host, cfg, oracle)
    sc = analyse.self_check(res, cfg, oracle)
    assert sc.ok, f"{name} / {host}: " + "; ".join(sc.problems)


@needs_ssh
@pytest.mark.parametrize("name", sorted(CONFIGS))
def test_check_never_disagrees_with_ssh(write_config, oracle, name):
    """The same assertion, over the probe hosts `check` chooses for itself."""
    cfg = write_config(_dedent(CONFIGS[name]), name=f"{name}.config")
    parsed = parse(cfg)
    _, resolutions = analyse.check(parsed, cfg, oracle)
    for res in resolutions:
        sc = analyse.self_check(res, cfg, oracle)
        assert sc.ok, f"{name} / {res.host}: " + "; ".join(sc.problems)


@needs_ssh
def test_every_winner_is_a_line_that_really_exists(write_config, oracle):
    """A reported file:line must be a line that actually holds that keyword."""
    cfg = write_config(_dedent(CONFIGS["many-keywords"]))
    res = analyse.resolve(parse(cfg), "target", cfg, oracle)
    text = cfg.read_text().splitlines()
    for key, directive in res.winners.items():
        line = text[directive.lineno - 1]
        assert directive.keyword in line, (
            f"{key} attributed to {directive.where}, but that line reads {line!r}"
        )
