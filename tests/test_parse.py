from __future__ import annotations

from firstmatch.parse import parse, split_line


class TestSplitLine:
    def test_plain(self):
        assert split_line("  User bob") == ("User", ["bob"])

    def test_equals_with_and_without_spaces(self):
        # ssh accepts all three spellings, so the parser has to.
        assert split_line("User=bob") == ("User", ["bob"])
        assert split_line("User = bob") == ("User", ["bob"])
        assert split_line("Host=example") == ("Host", ["example"])

    def test_quoted_argument_stays_one_token(self):
        kw, args = split_line('ProxyCommand "/usr/bin/with space" -x')
        assert kw == "ProxyCommand"
        assert args == ["/usr/bin/with space", "-x"]

    def test_comments_and_blanks_carry_nothing(self):
        assert split_line("") is None
        assert split_line("   ") is None
        assert split_line("# Host example") is None

    def test_unbalanced_quotes_do_not_raise(self):
        kw, args = split_line('ProxyCommand "unclosed')
        assert kw == "ProxyCommand"
        assert args  # ssh would reject the file; we still want to report the line


class TestBlocks:
    def test_directives_before_any_host_are_global(self):
        p = parse_text("Compression yes\nHost a\n  User u\n")
        assert p.blocks[0].kind == "toplevel"
        assert p.blocks[0].patterns == ("*",)
        assert [d.key for d in p.blocks[0].directives] == ["compression"]

    def test_no_phantom_toplevel_when_file_opens_with_host(self):
        p = parse_text("Host a\n  User u\n")
        assert [b.kind for b in p.blocks] == ["host"]

    def test_host_patterns_are_whitespace_separated(self):
        p = parse_text("Host a b c\n  User u\n")
        assert p.blocks[0].patterns == ("a", "b", "c")

    def test_comma_host_pattern_stays_one_pattern(self):
        # Which is the whole reason the comma-in-host finding exists.
        p = parse_text("Host a,b\n  User u\n")
        assert p.blocks[0].patterns == ("a,b",)

    def test_match_criteria_pair_up(self):
        p = parse_text("Match host a,b user bob final\n  Port 22\n")
        assert p.blocks[0].criteria == (("host", "a,b"), ("user", "bob"), ("final", None))
        assert p.blocks[0].is_final

    def test_negated_match_criterion_keeps_its_bang(self):
        p = parse_text("Match !host a\n  Port 22\n")
        assert p.blocks[0].criteria == (("!host", "a"),)

    def test_keywords_are_case_insensitive(self):
        p = parse_text("HOST a\n  uSeR bob\n")
        assert p.blocks[0].kind == "host"
        assert p.blocks[0].directives[0].key == "user"
        assert p.blocks[0].directives[0].keyword == "uSeR"


class TestInclude:
    def test_missing_glob_and_missing_literal_are_both_recorded(self, tmp_path):
        cfg = tmp_path / "config"
        cfg.write_text(
            f"Include {tmp_path}/none.d/*.conf\nInclude {tmp_path}/typo\nHost a\n  User u\n"
        )
        p = parse(cfg)
        kinds = {(m.is_glob, m.pattern.endswith("typo")) for m in p.missing_includes}
        assert len(p.missing_includes) == 2
        assert (True, False) in kinds
        assert (False, True) in kinds

    def test_included_blocks_are_spliced_in_order(self, tmp_path):
        (tmp_path / "inc.conf").write_text("Host inner\n  User inneruser\n")
        cfg = tmp_path / "config"
        cfg.write_text(f"Host first\n  User a\nInclude {tmp_path}/inc.conf\nHost last\n  User z\n")
        p = parse(cfg)
        assert [b.patterns for b in p.blocks] == [("first",), ("inner",), ("last",)]

    def test_include_inside_a_host_block_is_guarded_by_it(self, tmp_path):
        """An Include under `Host work` is only read when `Host work` matches."""
        (tmp_path / "inc.conf").write_text("Host inner\n  User inneruser\n")
        cfg = tmp_path / "config"
        cfg.write_text(f"Host work\n  Include {tmp_path}/inc.conf\n")
        p = parse(cfg)
        inner = next(b for b in p.blocks if b.patterns == ("inner",))
        assert [g.patterns for g in inner.guards] == [("work",)]

    def test_toplevel_include_is_unguarded(self, tmp_path):
        (tmp_path / "inc.conf").write_text("Host inner\n  User u\n")
        cfg = tmp_path / "config"
        cfg.write_text(f"Include {tmp_path}/inc.conf\n")
        inner = next(b for b in parse(cfg).blocks if b.patterns == ("inner",))
        assert inner.guards == ()

    def test_block_opened_in_an_included_file_does_not_escape_it(self, tmp_path):
        """Verified against ssh: the line after the Include belongs to the outer block.

        The included file opens `Host inner` and never closes it. `Port 2299`
        sits after the Include in the *outer* file and must stay with
        `Host outer`.
        """
        (tmp_path / "inc.conf").write_text("Host inner\n  User inneruser\n")
        cfg = tmp_path / "config"
        cfg.write_text(f"Host outer\n  Include {tmp_path}/inc.conf\n  Port 2299\n")
        p = parse(cfg)
        outer = next(b for b in p.blocks if b.patterns == ("outer",))
        assert [d.key for d in outer.directives] == ["port"]

    def test_recursive_include_terminates(self, tmp_path):
        cfg = tmp_path / "config"
        cfg.write_text(f"Include {tmp_path}/config\nHost a\n  User u\n")
        p = parse(cfg)  # must not hang or blow the stack
        assert any(b.patterns == ("a",) for b in p.blocks)


def parse_text(text: str, tmp=None):
    import tempfile
    from pathlib import Path

    d = Path(tempfile.mkdtemp())
    p = d / "config"
    p.write_text(text, encoding="utf-8")
    return parse(p)
