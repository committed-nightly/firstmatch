from __future__ import annotations

from firstmatch import analyse
from firstmatch.parse import parse

from .conftest import needs_ssh


def codes(findings):
    return [f.code for f in findings]


def at(findings, code):
    return [f for f in findings if f.code == code]


@needs_ssh
class TestShadowed:
    def test_general_block_first_kills_the_specific_one(self, write_config, oracle):
        cfg = write_config(
            "Host *\n    User deploy\n\nHost github.com\n    User git\n"
        )
        findings, _ = analyse.check(parse(cfg), cfg, oracle)
        (f,) = at(findings, "shadowed")
        assert f.where.endswith(":5")
        assert "User" in f.message
        # `Host *` beats a later block for every host, not just the probed ones.
        assert f.certainty == "always"

    def test_specific_block_first_is_clean(self, write_config, oracle):
        cfg = write_config(
            "Host github.com\n    User git\n\nHost *\n    User deploy\n"
        )
        findings, _ = analyse.check(parse(cfg), cfg, oracle)
        assert at(findings, "shadowed") == []

    def test_accumulating_keyword_is_never_shadowed(self, write_config, oracle):
        """Two IdentityFile lines are the documented idiom, not a bug."""
        cfg = write_config(
            "Host *\n    IdentityFile ~/.ssh/id_a\n\nHost gh\n    IdentityFile ~/.ssh/id_b\n"
        )
        findings, _ = analyse.check(parse(cfg), cfg, oracle)
        assert findings == []

    def test_setenv_twice_in_one_block_is_reported_with_the_one_line_fix(
        self, write_config, oracle
    ):
        cfg = write_config("Host h\n    SetEnv A=1\n    SetEnv B=2\n")
        findings, _ = analyse.check(parse(cfg), cfg, oracle)
        (f,) = at(findings, "shadowed")
        assert f.where.endswith(":3")
        assert "same block" in f.detail
        assert "`SetEnv A=1 B=2`" in f.detail

    def test_a_keyword_the_general_block_does_not_set_survives(self, write_config, oracle):
        cfg = write_config("Host *\n    User deploy\n\nHost gh\n    Port 443\n")
        findings, _ = analyse.check(parse(cfg), cfg, oracle)
        assert findings == []


@needs_ssh
class TestFinalAndCanonical:
    def test_match_final_assignment_that_lost_is_reported_as_final_loses(
        self, write_config, oracle
    ):
        cfg = write_config(
            "Match final host prod\n    User finaluser\nHost prod\n    User realuser\n"
        )
        findings, _ = analyse.check(parse(cfg), cfg, oracle)
        (f,) = at(findings, "final-loses")
        assert f.where.endswith(":2")
        assert "Moving it earlier in the file will not help" in f.detail

    def test_match_final_may_still_set_an_untouched_keyword(self, write_config, oracle):
        cfg = write_config(
            "Match final host prod\n    Port 2022\nHost prod\n    User realuser\n"
        )
        findings, _ = analyse.check(parse(cfg), cfg, oracle)
        assert findings == []

    def test_canonical_block_is_dead_when_canonicalisation_is_off(self, write_config, oracle):
        cfg = write_config("Match canonical host prod\n    Port 2200\nHost *\n    User u\n")
        findings, _ = analyse.check(parse(cfg), cfg, oracle)
        assert at(findings, "canonical-never")

    def test_canonical_block_is_live_when_canonicalisation_is_on(self, write_config, oracle):
        cfg = write_config(
            "CanonicalizeHostname yes\nCanonicalDomains example.com\n"
            "Match canonical host *.example.com\n    Port 2200\nHost *\n    User u\n"
        )
        findings, _ = analyse.check(parse(cfg), cfg, oracle)
        assert at(findings, "canonical-never") == []


@needs_ssh
class TestStaticFindings:
    def test_negation_only_host_never_matches(self, write_config, oracle):
        cfg = write_config("Host !legacy\n    User u\n")
        assert "never-matches" in codes(analyse.static_findings(parse(cfg)))

    def test_negation_with_a_positive_pattern_is_fine(self, write_config, oracle):
        cfg = write_config("Host * !legacy\n    User u\n")
        assert "never-matches" not in codes(analyse.static_findings(parse(cfg)))

    def test_comma_in_host_pattern_suggests_the_whitespace_form(self, write_config):
        cfg = write_config("Host staging,prod\n    User u\n")
        (f,) = at(analyse.static_findings(parse(cfg)), "comma-in-host")
        assert "`Host staging prod`" in f.detail

    def test_match_host_commas_are_not_flagged(self, write_config):
        cfg = write_config("Match host staging,prod\n    User u\n")
        assert at(analyse.static_findings(parse(cfg)), "comma-in-host") == []

    def test_missing_include_messages_distinguish_glob_from_typo(self, write_config, tmp_path):
        cfg = write_config(
            f"Include {tmp_path}/none.d/*.conf\nInclude {tmp_path}/typo\nHost a\n    User u\n"
        )
        found = at(analyse.static_findings(parse(cfg)), "include-missing")
        assert len(found) == 2
        assert any("matches no file" in f.message for f in found)
        assert any("does not exist" in f.message for f in found)


@needs_ssh
class TestProbeHosts:
    def test_literal_names_are_used(self, write_config):
        cfg = write_config("Host alpha beta\n    User u\n")
        assert analyse.probe_hosts(parse(cfg)) == ["alpha", "beta", analyse.CATCHALL_PROBE]

    def test_bare_star_alone_still_yields_a_host(self, write_config):
        cfg = write_config("Host *\n    User u\n")
        assert analyse.probe_hosts(parse(cfg)) == [analyse.CATCHALL_PROBE]

    def test_wildcard_pattern_gets_a_synthetic_name(self, write_config):
        cfg = write_config("Host git*\n    User u\n")
        assert analyse.probe_hosts(parse(cfg)) == ["gitwild", analyse.CATCHALL_PROBE]

    def test_negated_and_comma_patterns_are_not_probe_hosts(self, write_config):
        cfg = write_config("Host !legacy\n    User u\nHost a,b\n    User v\n")
        assert analyse.probe_hosts(parse(cfg)) == [analyse.CATCHALL_PROBE]

    def test_catchall_probe_is_always_present(self, write_config):
        """Without it a trailing `Host *` block looks dead, and it is not."""
        cfg = write_config("Host a\n    User u\n")
        assert analyse.CATCHALL_PROBE in analyse.probe_hosts(parse(cfg))


@needs_ssh
class TestUnevaluated:
    def test_match_user_is_declined_rather_than_guessed(self, write_config, oracle):
        """`Match user` depends on a User an earlier block may have set.

        Answering it would mean assuming the resolution this tool exists to
        compute, so the block is reported as not evaluated instead.
        """
        cfg = write_config("Match user bob\n    Port 2222\nHost *\n    User bob\n")
        res = analyse.resolve(parse(cfg), "anything", cfg, oracle)
        assert [b.lineno for b in res.unevaluated] == [1]

    def test_guarded_block_under_a_non_matching_host_contributes_nothing(
        self, write_config, oracle, tmp_path
    ):
        (tmp_path / "work.conf").write_text("Host *\n    User workuser\n")
        cfg = write_config(
            f"Host work\n    Include {tmp_path}/work.conf\nHost *\n    User homeuser\n"
        )
        res = analyse.resolve(parse(cfg), "elsewhere", cfg, oracle)
        assert res.predicted["user"] == ["homeuser"]
        # ...and when the guard does match, the included block applies.
        res = analyse.resolve(parse(cfg), "work", cfg, oracle)
        assert res.predicted["user"] == ["workuser"]
