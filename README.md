# firstmatch

Say which line of your ssh config actually won.

`ssh -G host` already tells you the values ssh will use. It never tells you
which line produced them, and it never mentions the lines that lost. So when
`ssh prod` logs in as the wrong user, `ssh -G` confirms the wrong user and
stops there, and you are left reading the file and counting blocks.

For most keywords ssh keeps the **first** value it finds and ignores every
later one. That is backwards from almost every other config format you use, and
it means the general block at the top of your file silently beats the specific
block at the bottom:

```
Host *
    User deploy        # this wins

Host github.com
    User git           # this never runs
```

Written for the moment you are sure your ssh config says one thing and ssh is
plainly doing another.

## Install

```
pip install git+https://github.com/committed-nightly/firstmatch
```

Python 3.10 or newer. No dependencies. Needs `ssh` on your PATH, because it asks
the real one rather than guessing — see [Why it shells out](#why-it-shells-out).

## Usage

Two questions. There is a config with five things wrong with it in
`examples/ssh_config`, so everything below is reproducible from a fresh clone.

What is dead:

```
$ firstmatch check -F examples/ssh_config -q
examples/ssh_config:12: shadowed: User never applies; examples/ssh_config:7 already set it
examples/ssh_config:16: shadowed: User never applies; examples/ssh_config:7 already set it
examples/ssh_config:29: final-loses: User in a `Match final` block never applies
examples/ssh_config:24: never-matches: Host !legacy.example.com matches no host at all
examples/ssh_config:20: comma-in-host: Host pattern 'db1,db2,db3' contains a comma and matches nothing
examples/ssh_config:31: include-missing: Include ~/.ssh/config.d/*.conf matches no file
```

Drop the `-q` and each one explains itself and suggests the fix. And which line
won:

```
$ firstmatch explain github.com -F examples/ssh_config
ssh github.com   effective configuration, and the line that set it

  identityfile         ~/.ssh/id_ed25519                   examples/ssh_config:9
                       ~/.ssh/id_github                    examples/ssh_config:13
  serveraliveinterval  30                                  examples/ssh_config:8
  user                 deploy                              examples/ssh_config:7

2 line(s) in this config will not be used for github.com:
  examples/ssh_config:12 User git                             lost to examples/ssh_config:7
  examples/ssh_config:29 User someoneelse                     lost to examples/ssh_config:7 (final blocks are read last, and last loses)
```

Compare that against `ssh -F examples/ssh_config -G github.com`, which agrees on
every value and names no line.

With no `-F`, both commands read `~/.ssh/config`. `-q` gives one grep-friendly
line per finding, `--json` gives the lot. `check` exits 0 when clean and 1 when
it found something, so it works as a CI gate.

## What it finds

Every one of these is silent in ssh itself. None of them is an error, a warning,
or a non-zero exit.

| | |
|---|---|
| `shadowed` | A keyword an earlier matching block already set. The classic is a `Host *` block at the top of the file. |
| `final-loses` | An assignment in a `Match final` block that loses anyway — see below. |
| `canonical-never` | A `Match canonical` block when `CanonicalizeHostname` is `no`, which is the default. The canonicalising pass never runs, so the block is never read. |
| `never-matches` | A pattern list of only negations, like `Host !legacy`. ssh needs a positive pattern to match before a negation can exclude anything, so this matches no host at all. |
| `comma-in-host` | `Host db1,db2,db3`. Host pattern lists are whitespace-separated, so this is one literal pattern and matches nothing. `Match host` really is comma-separated, which is where the habit comes from. |
| `include-missing` | An `Include` whose glob matches no file — or whose plain path does not exist. Both are silent; ssh exits 0 either way, so a typo costs you the whole file with no warning. |

A line is only reported when it is dead for **every** host tested, which
includes a synthetic host matching none of your named patterns. That is what
stops a trailing `Host *` — the recommended layout — being reported as dead
just because a specific block above it wins for a named host.

### Two that are worth spelling out

**`Match final` loses to everything.** ssh reads `final` blocks on a second pass
over the file, after the first pass has finished, and first-wins still applies
on that pass. So a `Match final` block can only ever set a keyword that no
ordinary block set — *regardless of where in the file it sits*. A `Match final`
at the very top still loses to a `Host *` at the very bottom. The word reads
like "this one wins"; it means "last to speak", and under first-wins, last
loses.

**`SetEnv` does not accumulate and `SendEnv` does.** Same shape of argument,
adjacent in the man page, opposite behaviour. Worse, `SetEnv` does not
accumulate across two lines of the *same* block:

```
Host h
    SetEnv AAA=1
    SetEnv BBB=2       # lost. ssh sends AAA only.
```

To set both, put them on one line: `SetEnv AAA=1 BBB=2`. firstmatch says so, with
your values filled in.

## It will not run your `Match exec`

`ssh -G` evaluates `Match exec`, and evaluating it means running the command —
no connection, no prompt. So pointing any `ssh -G`-based tool at a config you
were handed is arbitrary code execution dressed as a lint. firstmatch refuses
such a config before it invokes ssh at all:

```
$ firstmatch check -F theirs.config
theirs.config:1: this config contains `Match exec`, and firstmatch will not run it.
...
If this config is yours and you want it evaluated, pass --allow-exec.
```

With `--allow-exec` the block is evaluated properly and used, rather than run
and then ignored.

## Why it shells out

OpenSSH's pattern matcher has negation, a separator that differs between `Host`
and `Match host`, and the rule that an all-negation list matches nothing. A
second implementation of that would be confidently wrong in exactly the cases
you reach for this tool. So firstmatch does not match patterns: it writes a
two-line config with a sentinel value, runs `ssh -G`, and reads back which block
won. `ssh -G` costs about four milliseconds and needs no network.

It then goes one step further. Having attributed each value to a line, it
compares the value it predicted against what `ssh -G` actually reports. A
mismatch means firstmatch picked the wrong line, so it says so on stderr and
exits 3 — because the attribution is the whole product, and it is the one part
ssh cannot confirm directly. `tests/test_crosscheck.py` runs that comparison
over eleven configs and ten hosts on every push.

The keyword accumulation table in `keywords.py` was derived the same way, by
probing the ssh on the box rather than reading the man page.
`tests/test_semantics.py` re-derives it and fails if a future OpenSSH moves a
keyword between the groups.

## What it does not do

- **`Match user`, `Match tagged`.** Resolving these means knowing the `User` or
  `Tag` an earlier block may have set, which is the resolution being computed.
  Rather than guess, firstmatch lists the block under "not evaluated" and says
  the values are incomplete. A tool that quietly guessed here would be wrong
  invisibly.
- **Pattern subsumption in the abstract.** "Is this line dead for every
  conceivable hostname" is not answered; "is it dead for every host your config
  names, plus one that matches only your wildcards" is. Findings carry
  `certainty: always` when the winning block is a bare `Host *` and so provably
  beats the loser for every host, and `probed` otherwise.
- **`sshd_config`.** This is the client side only. Server config is a different
  file with different semantics — there is no `Host` keyword and `Match` works
  differently.
- **Value validation.** It will not tell you `Port banana` is invalid. ssh says
  that loudly already, and this tool is about the things ssh says nothing about.

## Prior art

[`sshd-lint`](https://github.com/capitan0n/sshd-lint) analyses `sshd_config` for
security hardening — server side, different question.
[`sshconfig-lint`](https://marketplace.visualstudio.com/items?itemName=NoahThiering.sshconfig-lint)
is a VS Code extension that validates values and flags duplicate blocks in the
editor. The usual advice for the ordering trap is "run `ssh -G` and read the
output", which gives you values without provenance. None of them name the line,
which is the thing you want at the moment you care.

## Licence

MIT.
