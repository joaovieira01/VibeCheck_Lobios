import json
import stat
import zipfile
from pathlib import Path

import pytest

from app import repo_scan
from app.repo_scan import RepositoryScanError, scan_repository
from app.scanner import ScanTimeout
from scripts.scan_repo import main


def _write_secret(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('SECRET_KEY = "local-example-secret"\n', encoding="utf-8")


def test_scan_repository_directory_aggregates_findings_and_relative_paths(tmp_path):
    _write_secret(tmp_path / "src" / "settings.py")
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "sample"}\n', encoding="utf-8")

    report = scan_repository(tmp_path)

    assert report["filesAnalyzed"] == [
        "package.json",
        "requirements.txt",
        "src/settings.py",
    ]
    assert report["findingsByFile"]["src/settings.py"][0]["id"] == "hardcoded-secret"
    assert report["countsBySeverity"] == {"Crítica": 1}
    assert report["countsByOwasp"] == {"A04 - Falhas criptográficas": 1}
    assert report["filesNotAnalyzed"] == []
    assert report["partial"] is False
    assert report["durationSeconds"] >= 0


def test_scan_repository_zip_extracts_temporarily_and_scans(tmp_path):
    archive_path = tmp_path / "repository.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("src/settings.py", 'SECRET_KEY = "zip-example-secret"\n')

    report = scan_repository(archive_path)

    assert report["filesAnalyzed"] == ["src/settings.py"]
    assert "src/settings.py" in report["findingsByFile"]


def test_scan_repository_ignores_directories_unsupported_large_and_binary_files(tmp_path):
    _write_secret(tmp_path / "node_modules" / "dependency" / "main.py")
    _write_secret(tmp_path / ".git" / "hooks" / "hook.py")
    _write_secret(tmp_path / "large.py")
    (tmp_path / "large.py").write_bytes(b"x" * (repo_scan.MAX_FILE_BYTES + 1))
    (tmp_path / "image.py").write_bytes(b"\x00\x01\x02")
    (tmp_path / "notes.txt").write_text("not source", encoding="utf-8")

    report = scan_repository(tmp_path)

    assert report["filesAnalyzed"] == []
    ignored = {(item["path"], item["reason"]) for item in report["ignoredFiles"]}
    assert ("node_modules", "diretório ignorado") in ignored
    assert (".git", "diretório ignorado") in ignored
    assert ("large.py", "arquivo acima de 1 MB") in ignored
    assert ("image.py", "arquivo binário") in ignored
    assert ("notes.txt", "extensão não suportada") in ignored


def test_scan_repository_timeout_returns_partial_and_unanalyzed_files(tmp_path, monkeypatch):
    _write_secret(tmp_path / "a.py")
    _write_secret(tmp_path / "b.py")

    def timeout(*args, **kwargs):
        raise ScanTimeout()

    monkeypatch.setattr(repo_scan, "scan_source", timeout)
    report = scan_repository(tmp_path)

    assert report["filesAnalyzed"] == []
    assert report["filesNotAnalyzed"] == ["a.py", "b.py"]
    assert report["partial"] is True


def test_scan_repository_zero_budget_reports_all_files_as_unanalyzed(tmp_path):
    _write_secret(tmp_path / "source.py")

    report = scan_repository(tmp_path, time_budget_seconds=0)

    assert report["filesAnalyzed"] == []
    assert report["filesNotAnalyzed"] == ["source.py"]
    assert report["partial"] is True


@pytest.mark.parametrize("unsafe_name", ["../outside.py", "/outside.py", "C:\\outside.py"])
def test_zip_rejects_zip_slip_and_absolute_paths(tmp_path, unsafe_name):
    archive_path = tmp_path / "malicious.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(unsafe_name, "SECRET_KEY = 'must-not-extract'\n")

    with pytest.raises(RepositoryScanError, match="caminho inseguro"):
        scan_repository(archive_path)
    assert not (tmp_path.parent / "outside.py").exists()


def test_zip_rejects_symbolic_links(tmp_path):
    archive_path = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("linked.py")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(info, "target.py")

    with pytest.raises(RepositoryScanError, match="link ou tipo inseguro"):
        scan_repository(archive_path)


def test_zip_rejects_more_than_2000_files(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_scan, "MAX_ZIP_FILES", 2)
    archive_path = tmp_path / "too-many-files.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for index in range(3):
            archive.writestr(f"{index}.py", "pass\n")

    with pytest.raises(RepositoryScanError, match="excede os limites"):
        scan_repository(archive_path)


def test_zip_rejects_more_than_50_mb_expanded(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_scan, "MAX_ZIP_BYTES", 8)
    archive_path = tmp_path / "too-large.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.py", "x" * 9)

    with pytest.raises(RepositoryScanError, match="excede os limites"):
        scan_repository(archive_path)


def test_cli_sarif_includes_required_fields_and_line_region(tmp_path, capsys):
    _write_secret(tmp_path / "src" / "settings.py")

    exit_code = main([str(tmp_path), "--format", "sarif"])

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert output["version"] == "2.1.0"
    run = output["runs"][0]
    assert run["tool"]["driver"]["name"] == "VibeCheck"
    assert run["tool"]["driver"]["rules"][0]["id"] == "hardcoded-secret"
    result = run["results"][0]
    assert result["ruleId"] == "hardcoded-secret"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/settings.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_cli_fail_on_respects_severity_threshold(tmp_path, capsys):
    source = tmp_path / "settings.py"
    source.write_text("DEBUG = True\n", encoding="utf-8")

    assert main([str(tmp_path), "--format", "json", "--fail-on", "Crítica"]) == 0
    capsys.readouterr()
    assert main([str(tmp_path), "--format", "json", "--fail-on", "Alta"]) == 1
    capsys.readouterr()
    assert main([str(tmp_path), "--format", "json"]) == 0


def test_cli_help_is_in_portuguese(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])

    output = capsys.readouterr().out
    assert exit_info.value.code == 0
    assert "Uso:" in output
    assert "argumentos:" in output
    assert "mostra esta ajuda e encerra" in output


def test_cli_errors_do_not_expose_input_paths(tmp_path, capsys):
    private_path = tmp_path / "missing-private-repository.zip"

    assert main([str(private_path)]) == 2
    error = capsys.readouterr().err
    assert "Erro:" in error
    assert str(tmp_path) not in error
