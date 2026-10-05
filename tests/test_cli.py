from __future__ import annotations

import json

import pytest

from firstmatch.cli import main

from .conftest import needs_ssh

CLEAN = "Host github.com\n    User git\n\nHost *\n    ServerAliveInterval 30\n"
DIRTY = "Host *\n    User deploy\n\nHost github.com\n    User git\n"


@needs_ssh
class TestExitCodes:
    def test_clean_config_is_zero(self, write_config, capsys):
        assert main(["check", "-F", str(write_config(CLEAN))]) == 0
        assert "no dead lines" in capsys.readouterr().out

    def test_findings_are_one(self, write_config, capsys):
        assert main(["check", "-F", str(write_config(DIRTY))]) == 1
        assert "shadowed" in capsys.readouterr().out

    def test_explain_is_zero_even_with_findings(self, write_config, capsys):
        # explain answers a question; it is not a pass/fail gate.
        assert main(["explain", "github.com", "-F", str(write_config(DIRTY))]) == 0

    def test_missing_file_is_a_usage_error(self, write_config, tmp_path):
        with pytest.raises(SystemExit) as exc:
            main(["check", "-F", str(tmp_path / "nope")])
        assert "no such file" in str(exc.value)

    def test_directory_instead_of_file(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            main(["check", "-F", str(tmp_path)])
        assert "is a directory" in str(exc.value)


@needs_ssh
class TestMatchExecGate:
    EXEC_CFG = 'Match exec "/bin/true"\n    User execuser\nHost *\n    User plain\n'

    def test_refused_by_default(self, write_config, capsys):
        rc = main(["check", "-F", str(write_config(self.EXEC_CFG))])
        assert rc == 2
        err = capsys.readouterr().err
        assert "will not run it" in err
        assert "--allow-exec" in err

    def test_not_run_by_default(self, write_config, tmp_path, capsys):
        """The refusal has to come before ssh is invoked, or it is decorative."""
        canary = tmp_path / "canary"
        cfg = write_config(
            f'Match exec "/usr/bin/touch {canary}"\n    User e\nHost *\n    User plain\n'
        )
        assert main(["check", "-F", str(cfg)]) == 2
        assert not canary.exists(), "ssh -G ran the Match exec command despite the refusal"

    def test_allowed_with_the_flag(self, write_config, capsys):
        rc = main(["check", "-F", str(write_config(self.EXEC_CFG)), "--allow-exec"])
        assert rc in (0, 1)
        assert "will not run it" not in capsys.readouterr().err

    def test_exec_block_is_evaluated_once_allowed(self, write_config, capsys):
        """With consent, the exec block must actually be used, not just permitted."""
        cfg = write_config(self.EXEC_CFG)
        main(["explain", "anyhost", "-F", str(cfg), "--allow-exec"])
        out = capsys.readouterr().out
        assert "execuser" in out
        assert "not evaluated" not in out


@needs_ssh
class TestJson:
    def test_check_json_shape(self, write_config, capsys):
        main(["check", "-F", str(write_config(DIRTY)), "--json"])
        doc = json.loads(capsys.readouterr().out)
        assert doc["self_check"] == {"ok": True, "declined": False, "problems": []}
        assert [f["code"] for f in doc["findings"]] == ["shadowed"]
        assert doc["findings"][0]["certainty"] == "always"
        assert doc["hosts_checked"]

    def test_explain_json_reports_files_read(self, write_config, capsys):
        cfg = write_config(DIRTY)
        main(["explain", "github.com", "-F", str(cfg), "--json"])
        doc = json.loads(capsys.readouterr().out)
        assert doc["files_read"] == [str(cfg)]


@needs_ssh
class TestOutput:
    def test_quiet_drops_the_explanations(self, write_config, capsys):
        main(["check", "-F", str(write_config(DIRTY)), "-q"])
        out = capsys.readouterr().out
        assert out.count("\n") == 1
        assert "ssh keeps the first" not in out

    def test_explain_names_the_line_for_each_value(self, write_config, capsys):
        cfg = write_config(DIRTY)
        main(["explain", "github.com", "-F", str(cfg)])
        out = capsys.readouterr().out
        assert f"{cfg}:2" in out  # User deploy, the line that wins
        assert f"{cfg}:5" in out  # User git, the line that loses
        assert "will not be used" in out

    def test_explain_all_includes_untouched_defaults(self, write_config, capsys):
        cfg = write_config(DIRTY)
        main(["explain", "github.com", "-F", str(cfg), "--all"])
        out = capsys.readouterr().out
        assert "(ssh default)" in out
        assert "batchmode" in out

    def test_host_flag_overrides_the_probe_set(self, write_config, capsys):
        main(["check", "-F", str(write_config(DIRTY)), "--host", "github.com", "--json"])
        doc = json.loads(capsys.readouterr().out)
        assert doc["hosts_checked"] == ["github.com"]
