"""Re-derive the accumulation table from the ssh on this box.

`keywords.ACCUMULATING` decides whether a repeated keyword is a bug or an
idiom. If it is wrong in one direction firstmatch misses real dead lines; if it
is wrong in the other it flags correct configuration, which is the worse
failure. Neither is detectable by reading the code, so the table is checked
against the binary that will actually run.

If OpenSSH ever moves a keyword between the two groups, this is the test that
fails, and the message tells you which way it moved.
"""

from __future__ import annotations

import pytest

from firstmatch.keywords import ACCUMULATING, FIRST_WINS_PROBED
from firstmatch.oracle import Oracle

from .conftest import needs_ssh

# (keyword, value in the specific block, value in the general block). The two
# values share no token, because a shared token makes the probe report
# accumulation that is not there -- which is exactly how the first draft of
# this table wrongly listed ProxyCommand as accumulating.
PROBES = [
    ("IdentityFile", "/tmp/fm-kaaa", "/tmp/fm-kbbb"),
    ("CertificateFile", "/tmp/fm-caaa", "/tmp/fm-cbbb"),
    ("LocalForward", "7001 aaa.invalid:22", "7002 bbb.invalid:22"),
    ("RemoteForward", "7003 aaa.invalid:22", "7004 bbb.invalid:22"),
    ("DynamicForward", "7005", "7006"),
    ("SendEnv", "FMAAA", "FMBBB"),
    ("SetEnv", "FMAAA=1", "FMBBB=2"),
    ("RemoteCommand", "aaa_cmd", "bbb_cmd"),
    ("LocalCommand", "aaa_cmd", "bbb_cmd"),
    ("PermitRemoteOpen", "aaa.invalid:1", "bbb.invalid:2"),
    ("CanonicalDomains", "aaa.invalid", "bbb.invalid"),
    ("UserKnownHostsFile", "/tmp/fm-ukhaaa", "/tmp/fm-ukhbbb"),
    ("GlobalKnownHostsFile", "/tmp/fm-gkhaaa", "/tmp/fm-gkhbbb"),
    ("KnownHostsCommand", "/tmp/fm-aaa", "/tmp/fm-bbb"),
    ("ProxyCommand", "aaa_cmd", "bbb_cmd"),
    ("ProxyJump", "aaa.invalid", "bbb.invalid"),
    ("User", "useraaa", "userbbb"),
    ("Port", "2201", "2202"),
    ("Hostname", "aaa.invalid", "bbb.invalid"),
    ("ConnectTimeout", "11", "22"),
    ("Ciphers", "aes128-ctr", "aes256-ctr"),
    ("MACs", "hmac-sha2-256", "hmac-sha2-512"),
    ("KexAlgorithms", "curve25519-sha256", "ecdh-sha2-nistp256"),
]

HOST = "fm-probehost"


def _observe(oracle: Oracle, tmp_path, keyword: str, v1: str, v2: str) -> bool:
    """True if the second block's value survives, i.e. the keyword accumulates."""
    cfg = tmp_path / f"probe-{keyword}"
    cfg.write_text(
        f"Host {HOST}\n  {keyword} {v1}\nHost *\n  {keyword} {v2}\n", encoding="utf-8"
    )
    res = oracle.run(cfg, HOST)
    assert res.ok, f"ssh -G rejected the probe for {keyword}: {res.stderr}"
    body = " ".join(res.values.get(keyword.lower(), []))
    # Compare whole tokens, not substrings. A substring test here reported Port
    # and ConnectTimeout as accumulating, because "2202" and "22" turn up inside
    # unrelated text -- and str.strip() takes a character set, not a suffix, so
    # the attempt to normalise made it worse.
    tokens = {t.replace("[", "").replace("]", "") for t in body.split()}
    tok1, tok2 = v1.split()[-1], v2.split()[-1]
    assert tok1 in tokens, (
        f"{keyword}: the first block's value {tok1!r} is absent from {body!r}; "
        "the probe itself is wrong"
    )
    return tok2 in tokens


@needs_ssh
@pytest.mark.parametrize("keyword,v1,v2", PROBES, ids=[p[0] for p in PROBES])
def test_accumulation_table_matches_this_ssh(oracle, tmp_path, keyword, v1, v2):
    key = keyword.lower()
    accumulates_really = _observe(oracle, tmp_path, keyword, v1, v2)
    declared = key in ACCUMULATING
    if accumulates_really and not declared:
        pytest.fail(
            f"{keyword} accumulates on this ssh but is not in keywords.ACCUMULATING. "
            "firstmatch will report a live line as shadowed -- add it."
        )
    if declared and not accumulates_really:
        pytest.fail(
            f"{keyword} is in keywords.ACCUMULATING but this ssh keeps only the first "
            "value. firstmatch will miss a real dead line -- remove it."
        )


@needs_ssh
def test_setenv_does_not_accumulate_even_within_one_block(oracle, tmp_path):
    """The trap worth a test of its own.

    SendEnv accumulates across two lines of one block. SetEnv, same shape of
    argument and the next entry in the man page, does not -- the second line is
    simply lost. The fix is to put both assignments on one line, so that is
    asserted too.
    """
    cfg = tmp_path / "setenv"
    cfg.write_text("Host h\n  SetEnv FMAAA=1\n  SetEnv FMBBB=2\n", encoding="utf-8")
    got = oracle.run(cfg, "h").values.get("setenv", [])
    assert got == ["FMAAA=1"], f"expected only the first SetEnv to survive, got {got}"

    cfg.write_text("Host h\n  SendEnv FMAAA\n  SendEnv FMBBB\n", encoding="utf-8")
    got = oracle.run(cfg, "h").values.get("sendenv", [])
    assert got == ["FMAAA", "FMBBB"], f"SendEnv should accumulate, got {got}"

    cfg.write_text("Host h\n  SetEnv FMAAA=1 FMBBB=2\n", encoding="utf-8")
    got = oracle.run(cfg, "h").values.get("setenv", [])
    assert got == ["FMAAA=1", "FMBBB=2"], f"one-line form should set both, got {got}"


@needs_ssh
def test_match_final_loses_to_a_block_below_it(oracle, tmp_path):
    """`Match final` at the top of the file still loses to `Host *` at the bottom.

    This is the claim behind the final-loses finding, and it is surprising
    enough that it should be pinned to real ssh rather than to our reading of
    the man page.
    """
    cfg = tmp_path / "final"
    cfg.write_text(
        "Match final host fh\n  User finaluser\n  Port 2022\nHost *\n  User plain\n",
        encoding="utf-8",
    )
    vals = oracle.run(cfg, "fh").values
    assert vals["user"] == ["plain"], "a final block should lose a keyword already set"
    # ...but it does get to set one nothing else set, which is why the finding
    # is per-keyword rather than per-block.
    assert vals["port"] == ["2022"]


@needs_ssh
def test_all_negation_pattern_list_matches_nothing(oracle, tmp_path):
    cfg = tmp_path / "neg"
    cfg.write_text("Host !excluded\n  User negonly\nHost *\n  User plain\n", encoding="utf-8")
    assert oracle.run(cfg, "anything").values["user"] == ["plain"]
    assert oracle.run(cfg, "excluded").values["user"] == ["plain"]


@needs_ssh
def test_host_pattern_list_is_whitespace_separated_but_match_host_is_commas(oracle, tmp_path):
    """The asymmetry behind the comma-in-host finding."""
    cfg = tmp_path / "commas"
    cfg.write_text("Host aaa,bbb\n  User commauser\nHost *\n  User plain\n", encoding="utf-8")
    assert oracle.run(cfg, "aaa").values["user"] == ["plain"]
    assert oracle.run(cfg, "bbb").values["user"] == ["plain"]

    cfg.write_text(
        "Match host aaa,bbb\n  User commauser\nHost *\n  User plain\n", encoding="utf-8"
    )
    assert oracle.run(cfg, "bbb").values["user"] == ["commauser"]


@needs_ssh
def test_missing_include_is_silent(oracle, tmp_path):
    """Both shapes of missing Include, since the non-glob one surprises people."""
    cfg = tmp_path / "inc"
    cfg.write_text(
        f"Include {tmp_path}/nothing.d/*.conf\n"
        f"Include {tmp_path}/typo-path\n"
        "Host *\n  User plain\n",
        encoding="utf-8",
    )
    res = oracle.run(cfg, "h")
    assert res.ok, "ssh should not complain about either missing Include"
    assert res.values["user"] == ["plain"]


@needs_ssh
def test_first_wins_control_group(oracle, tmp_path):
    """Nothing in FIRST_WINS_PROBED has quietly started accumulating."""
    probes = {k.lower(): (v1, v2) for k, v1, v2 in PROBES}
    for key in sorted(FIRST_WINS_PROBED):
        if key not in probes:
            continue
        keyword = next(k for k, _, _ in PROBES if k.lower() == key)
        v1, v2 = probes[key]
        assert not _observe(oracle, tmp_path, keyword, v1, v2), (
            f"{keyword} now accumulates; move it out of FIRST_WINS_PROBED into ACCUMULATING"
        )
