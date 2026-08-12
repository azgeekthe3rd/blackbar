from __future__ import annotations

import json
from pathlib import Path

import pytest

from blackbar.cli import EXIT_FOUND, EXIT_OK, EXIT_USAGE, main


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "app.log"
    path.write_text(
        "2024-03-01 login user=ops@acme.io ip=8.8.8.8\n2024-03-01 charge card=4111111111111111\n",
        encoding="utf-8",
    )
    return path


class TestScrubCommand:
    def test_writes_redacted_text_to_stdout(self, sample: Path, capsys) -> None:
        code = main(["scrub", str(sample)])
        out = capsys.readouterr().out
        assert code == EXIT_FOUND
        assert "ops@acme.io" not in out
        assert "[EMAIL]" in out and "[CREDIT_CARD]" in out
        assert "2024-03-01 login" in out  # non-PII survives

    def test_output_file(self, sample: Path, tmp_path: Path) -> None:
        destination = tmp_path / "clean.log"
        main(["scrub", str(sample), "-o", str(destination)])
        assert "[EMAIL]" in destination.read_text(encoding="utf-8")

    def test_strategy_selection(self, sample: Path, capsys) -> None:
        main(["scrub", str(sample), "--strategy", "mask"])
        out = capsys.readouterr().out
        assert "************1111" in out  # tail preserved, separators would be too
        assert "o**@acme.io" in out  # email keeps its domain

    def test_only_filter(self, sample: Path, capsys) -> None:
        main(["scrub", str(sample), "--only", "EMAIL"])
        out = capsys.readouterr().out
        assert "[EMAIL]" in out
        assert "8.8.8.8" in out

    def test_allow_literal(self, sample: Path, capsys) -> None:
        main(["scrub", str(sample), "--allow", "ops@acme.io"])
        assert "ops@acme.io" in capsys.readouterr().out

    def test_reads_stdin(self, capsys, monkeypatch) -> None:
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO("hi ops@acme.io"))
        main(["scrub", "-"])
        assert capsys.readouterr().out == "hi [EMAIL]"


class TestScanCommand:
    def test_json_report_omits_values(self, sample: Path, capsys) -> None:
        code = main(["scan", str(sample), "--json"])
        report = json.loads(capsys.readouterr().out)
        assert code == EXIT_FOUND
        assert report["counts"] == {"CREDIT_CARD": 1, "EMAIL": 1, "IPV4": 1}
        assert all("text" not in m for m in report["matches"])

    def test_show_values_opt_in(self, sample: Path, capsys) -> None:
        main(["scan", str(sample), "--json", "--show-values"])
        report = json.loads(capsys.readouterr().out)
        assert any(m.get("text") == "ops@acme.io" for m in report["matches"])

    def test_clean_file_exits_zero(self, tmp_path: Path, capsys) -> None:
        path = tmp_path / "clean.txt"
        path.write_text("nothing to see here", encoding="utf-8")
        assert main(["scan", str(path)]) == EXIT_OK
        assert "No PII detected" in capsys.readouterr().out

    def test_quiet_is_silent(self, sample: Path, capsys) -> None:
        assert main(["scan", str(sample), "--quiet"]) == EXIT_FOUND
        assert capsys.readouterr().out == ""


class TestErrors:
    def test_missing_file(self, capsys) -> None:
        assert main(["scan", "/nope/missing.txt"]) == EXIT_USAGE
        assert "no such file" in capsys.readouterr().err

    def test_unknown_entity_is_rejected(self) -> None:
        with pytest.raises(SystemExit):
            main(["scan", "--only", "NOT_A_THING"])


#: Realistic text that must survive untouched. Every line here is something a
#: naive regex scrubber mangles, which is the whole reason the validators exist.
CLEAN_CORPUS = [
    "Order #1234567890123456 shipped on 2024-03-01",
    "Build 1.2.3.4000 passed in 42s",
    "Listening on 127.0.0.1:8080 and 0.0.0.0:443",
    "Upstream 10.0.0.7 timed out after 30000ms",
    "Contact support@example.com for help",
    "SKU 4111-1111-1111-1112 is out of stock",
    "Elapsed 12:30:45 across 3 shards",
    "Invoice total 1234.56 for account 000000000",
    "git rev-parse HEAD -> a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    "Retry 3 of 5 after 1500ms backoff",
]


@pytest.mark.parametrize("line", CLEAN_CORPUS)
def test_no_false_positives_on_realistic_text(line: str) -> None:
    from blackbar import scrub

    assert scrub(line) == line
