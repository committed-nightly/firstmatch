"""Which ssh_config keywords accumulate, and which keep only the first value.

This table decides whether a repeated keyword is a bug or an idiom, so getting
it wrong is the difference between a useful tool and one that flags correct
configuration. It was not copied from the man page. Every entry was derived by
putting the keyword in two matching blocks with different values, running the
real `ssh -G`, and seeing whether the second value survived.

`tests/test_semantics.py` re-derives the whole table that way and fails if this
file disagrees with the ssh on the box. If a future OpenSSH moves a keyword
between the two groups, that test is where you will hear about it.

The surprise, if you are skimming: SetEnv does *not* accumulate, and SendEnv
does. They take the same shape of argument, sit next to each other in the man
page, and behave in opposite ways. Worse, SetEnv does not even accumulate
across two lines of the *same* block -- `SetEnv A=1` then `SetEnv B=2` sets
only A. To set two variables you need them on one line.
"""

from __future__ import annotations

# A later assignment of one of these ADDS to the earlier one. Both lines are
# live, and reporting the second as shadowed would be a false positive.
ACCUMULATING = frozenset(
    {
        "certificatefile",
        "dynamicforward",
        "identityfile",
        "localforward",
        "remoteforward",
        "sendenv",
    }
)

# Keywords whose value ssh takes from the first matching block and never
# revisits. This is not exhaustive -- it does not need to be, because anything
# not in ACCUMULATING is treated as first-wins. It exists so the semantics test
# has a control group: if one of these ever starts accumulating, that is a
# finding too.
FIRST_WINS_PROBED = frozenset(
    {
        "canonicaldomains",
        "channeltimeout",
        "ciphers",
        "connecttimeout",
        "globalknownhostsfile",
        "hostname",
        "ipqos",
        "kexalgorithms",
        "knownhostscommand",
        "localcommand",
        "loglevel",
        "macs",
        "permitremoteopen",
        "port",
        "proxycommand",
        "proxyjump",
        "remotecommand",
        "setenv",
        "user",
        "userknownhostsfile",
    }
)


def accumulates(key: str) -> bool:
    """True if a second assignment of `key` adds to the first rather than losing."""
    return key.lower() in ACCUMULATING


# Match criteria that take a pattern-list argument, as opposed to standing
# alone. `tagged` takes an argument too but resolving it needs the Tag that an
# earlier block may or may not have set, which is why analyse.py declines to
# evaluate it rather than guessing.
MATCH_WITH_ARG = frozenset({"host", "originalhost", "user", "localuser", "exec", "tagged"})
MATCH_STANDALONE = frozenset({"all", "canonical", "final"})
