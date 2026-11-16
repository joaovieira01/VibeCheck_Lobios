import json
import threading
from urllib.error import HTTPError, URLError

import pytest

from app.deps import DependencyCheckResult, check_dependencies
from app.service import run_analysis
from scripts.scan_file import main as scan_file_main
from scripts.scan_repo import main as scan_repo_main


class FakeHTTPClient:
    def __init__(self, *, packages=None, osv=None, errors=None):
        self.packages = packages or {}
        self.osv = osv or {}
        self.errors = errors or {}
        self.calls = []
        self.lock = threading.Lock()

    def get_json(self, url, timeout):
        with self.lock:
            self.calls.append(("GET", url, timeout))
        if url in self.errors:
            raise self.errors[url]
        if url not in self.packages:
            raise AssertionError(f"URL inesperada: {url}")
        return self.packages[url]

    def post_json(self, url, payload, timeout):
        with self.lock:
            self.calls.append(("POST", url, payload, timeout))
        if url in self.errors:
            raise self.errors[url]
        if url != "https://api.osv.dev/v1/querybatch":
            raise AssertionError(f"URL inesperada: {url}")
        return self.osv


def _http_404(url):
    return HTTPError(url, 404, "not found", {}, None)


def test_pinned_requirements_existing_package_queries_pypi_and_osv():
    pypi_url = "https://pypi.org/pypi/requests/json"
    client = FakeHTTPClient(
        packages={pypi_url: {"info": {"name": "requests"}}},
        osv={"results": [{"vulns": []}]},
    )

    result = check_dependencies(
        "requests==2.31.0\n", "requirements.txt", client=client
    )

    assert result.findings == []
    assert result.status == "concluida"
    assert result.packages_checked == 1
    assert [call[0] for call in client.calls].count("GET") == 1
    osv_call = next(call for call in client.calls if call[0] == "POST")
    assert osv_call[2] == {
        "queries": [
            {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.31.0"}
        ]
    }
    assert all(call[-1] == 3 for call in client.calls)


def test_fixed_npm_package_can_be_checked_and_reported_missing():
    npm_url = "https://registry.npmjs.org/does-not-exist"
    client = FakeHTTPClient(
        errors={npm_url: _http_404(npm_url)},
        osv={"results": [{"vulns": []}]},
    )

    result = check_dependencies(
        json.dumps({"dependencies": {"does-not-exist": "1.2.3"}}),
        "package.json",
        client=client,
    )

    finding = next(item for item in result.findings if item.id == "nonexistent-dependency")
    assert finding.severity == "Alta"
    assert "pacote inexistente, possível alucinação de IA ou typosquatting" in finding.description
    assert finding.locations == [1]


def test_known_vulnerability_reports_advisory_and_fixed_version():
    client = FakeHTTPClient(
        packages={"https://pypi.org/pypi/example/json": {"info": {"name": "example"}}},
        osv={
            "results": [
                {
                    "vulns": [
                        {
                            "id": "OSV-2024-123",
                            "aliases": ["GHSA-abcd-efgh-ijkl", "CVE-2024-1234"],
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "1.2.4"},
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                }
            ]
        },
    )

    result = check_dependencies(
        "example==1.2.3\n", "requirements.txt", client=client
    )

    finding = next(item for item in result.findings if item.id == "vulnerable-dependency")
    assert "CVE-2024-1234" in finding.title
    assert "1.2.4" in finding.description
    assert finding.locations == [1]


def test_osv_timeout_keeps_registry_result_and_marks_check_unavailable():
    client = FakeHTTPClient(
        packages={"https://pypi.org/pypi/example/json": {"info": {"name": "example"}}},
        errors={"https://api.osv.dev/v1/querybatch": TimeoutError("timeout")},
    )

    result = check_dependencies(
        "example==1.2.3\n", "requirements.txt", client=client
    )

    assert result.findings == []
    assert result.status == "indisponivel"


@pytest.mark.parametrize("error", [TimeoutError("timeout"), URLError("offline")])
def test_network_failure_marks_check_unavailable_without_fabricating_findings(error):
    url = "https://pypi.org/pypi/example/json"
    client = FakeHTTPClient(errors={url: error})

    result = check_dependencies(
        "example==1.2.3\n", "requirements.txt", client=client
    )

    assert result.findings == []
    assert result.status == "indisponivel"


def test_server_error_does_not_mean_package_is_missing():
    url = "https://registry.npmjs.org/example"
    client = FakeHTTPClient(
        errors={url: HTTPError(url, 500, "server error", {}, None)}
    )

    result = check_dependencies(
        '{"dependencies":{"example":"1.2.3"}}', "package.json", client=client
    )

    assert result.findings == []
    assert result.status == "indisponivel"


def test_malicious_package_name_is_rejected_before_request():
    client = FakeHTTPClient()

    result = check_dependencies(
        '{"dependencies":{"../../hostile":"1.2.3"}}',
        "package.json",
        client=client,
    )

    assert result.findings == []
    assert result.status == "indisponivel"
    assert client.calls == []


def test_only_first_fifty_packages_are_checked():
    names = [f"package-{index}" for index in range(51)]
    source = "\n".join(f"{name}==1.2.3" for name in names)
    packages = {
        f"https://pypi.org/pypi/{name}/json": {"info": {"name": name}}
        for name in names[:50]
    }
    client = FakeHTTPClient(
        packages=packages,
        osv={"results": [{"vulns": []} for _ in range(50)]},
    )

    result = check_dependencies(source, "requirements.txt", client=client)

    assert result.packages_checked == 50
    assert result.status == "limitada"
    assert len([call for call in client.calls if call[0] == "GET"]) == 50
    osv_call = next(call for call in client.calls if call[0] == "POST")
    assert len(osv_call[2]["queries"]) == 50


def test_unpinned_versions_are_not_sent_to_osv():
    url = "https://pypi.org/pypi/example/json"
    client = FakeHTTPClient(packages={url: {"info": {"name": "example"}}})

    result = check_dependencies(
        "example>=1.2\n", "requirements.txt", client=client
    )

    assert result.status == "concluida"
    assert [call[0] for call in client.calls] == ["GET"]


def test_python_pin_with_environment_marker_is_sent_to_osv():
    url = "https://pypi.org/pypi/example/json"
    client = FakeHTTPClient(
        packages={url: {"info": {"name": "example"}}},
        osv={"results": [{"vulns": []}]},
    )

    check_dependencies(
        'example[extra]==1.2.3; python_version >= "3.11"\n',
        "requirements.txt",
        client=client,
    )

    osv_call = next(call for call in client.calls if call[0] == "POST")
    assert osv_call[2]["queries"][0]["version"] == "1.2.3"


def test_run_analysis_can_enable_online_check_without_changing_default(monkeypatch):
    unavailable = DependencyCheckResult([], "indisponivel", 1)
    calls = []

    def fake_check(source, filename):
        calls.append((source, filename))
        return unavailable

    monkeypatch.setattr("app.service.check_dependencies", fake_check)
    monkeypatch.setenv("VIBECHECK_ONLINE_DEPS", "false")
    default_result = run_analysis(
        "requirements.txt",
        "example==1.2.3",
        max_source_bytes=1000,
        max_line_chars=1000,
    )
    assert "onlineDependencyCheck" not in default_result

    enabled_result = run_analysis(
        "requirements.txt",
        "example==1.2.3",
        max_source_bytes=1000,
        max_line_chars=1000,
        online_deps=True,
    )
    assert calls == [("example==1.2.3", "requirements.txt")]
    assert enabled_result["onlineDependencyCheck"]["message"] == (
        "Verificação online indisponível."
    )


def test_repository_scan_online_mode_includes_check_status_and_count(tmp_path, monkeypatch):
    from app.repo_scan import scan_repository

    (tmp_path / "requirements.txt").write_text("example==1.2.3\n", encoding="utf-8")
    monkeypatch.setattr(
        "app.repo_scan.check_dependencies",
        lambda source, filename: DependencyCheckResult([], "concluida", 1),
    )

    report = scan_repository(tmp_path, online_deps=True)

    assert report["onlineDependencyCheck"] == {
        "status": "concluida",
        "packagesChecked": 1,
    }


def test_cli_online_deps_options_reach_both_scan_paths(tmp_path, monkeypatch, capsys):
    checked = []

    def fake_check(source, filename):
        checked.append(filename)
        return DependencyCheckResult([], "indisponivel", 1)

    monkeypatch.setattr("app.service.check_dependencies", fake_check)
    file_path = tmp_path / "requirements.txt"
    file_path.write_text("example==1.2.3\n", encoding="utf-8")
    assert scan_file_main([str(file_path), "--online-deps"]) == 0
    file_output = json.loads(capsys.readouterr().out)
    assert file_output["onlineDependencyCheck"]["status"] == "indisponivel"

    monkeypatch.setattr("app.repo_scan.check_dependencies", fake_check)
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "requirements.txt").write_text(
        "example==1.2.3\n", encoding="utf-8"
    )
    assert scan_repo_main(
        [str(repository), "--online-deps", "--format", "json"]
    ) == 0
    repo_output = json.loads(capsys.readouterr().out)
    assert repo_output["onlineDependencyCheck"]["status"] == "indisponivel"
    assert checked == ["requirements.txt", "requirements.txt"]
