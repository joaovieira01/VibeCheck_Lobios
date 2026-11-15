import base64
import io
import json
import zipfile

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


PASSWORD = "senha-forte-123"


class FakeMailer:
    def send_password_reset(self, to_email, reset_url):
        return None


def _client(tmp_path, *, rate_limit=False, max_repo_zip_bytes=25_000_000):
    settings = Settings(
        db_path=tmp_path / "api.db",
        rate_limit_enabled=rate_limit,
        max_repo_zip_bytes=max_repo_zip_bytes,
        cors_origins=["http://localhost:5173"],
    )
    return TestClient(create_app(settings, FakeMailer()))


def _register(client, email="dev@example.com"):
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": PASSWORD},
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _zip_body(entries=None, filename="repository.zip"):
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, source in entries or [
            ("src/app.py", 'SECRET_KEY = "local-example-secret"\n')
        ]:
            archive.writestr(path, source)
    return {
        "filename": filename,
        "archiveBase64": base64.b64encode(content.getvalue()).decode("ascii"),
    }


def test_repository_upload_requires_login(tmp_path):
    client = _client(tmp_path)

    response = client.post("/api/repositories/analyses", json=_zip_body())

    assert response.status_code == 401


def test_repository_upload_persists_result_and_filters_history_by_user(tmp_path):
    client = _client(tmp_path)
    owner_headers = _register(client, "owner@example.com")
    other_headers = _register(client, "other@example.com")

    created = client.post(
        "/api/repositories/analyses",
        headers=owner_headers,
        json=_zip_body(),
    )

    assert created.status_code == 201, created.text
    result = created.json()
    assert result["analysisType"] == "repository"
    assert result["filename"] == "repository.zip"
    assert result["filesAnalyzed"] == ["src/app.py"]
    assert result["findingsByFile"]["src/app.py"][0]["id"] == "hardcoded-secret"
    assert result["countsBySeverity"] == {"Crítica": 1}
    assert result["findingsTruncated"] is False
    listed = client.get("/api/repositories/analyses", headers=owner_headers)
    assert listed.status_code == 200
    assert listed.json() == [
        {
            "id": result["id"],
            "filename": result["filename"],
            "createdAt": result["createdAt"],
            "countsBySeverity": result["countsBySeverity"],
            "countsByOwasp": result["countsByOwasp"],
            "filesAnalyzedCount": 1,
            "partial": result["partial"],
            "durationSeconds": result["durationSeconds"],
            "findingsTruncated": False,
            "truncatedFindingsCount": 0,
            "truncatedOccurrencesCount": 0,
        }
    ]
    assert client.get(
        f"/api/repositories/analyses/{result['id']}", headers=owner_headers
    ).json() == result
    assert client.get(
        "/api/repositories/analyses", headers=other_headers
    ).json() == []
    assert client.get(
        f"/api/repositories/analyses/{result['id']}", headers=other_headers
    ).status_code == 404
    assert client.get("/api/analyses", headers=owner_headers).json() == []
    assert client.get(
        f"/api/analyses/{result['id']}", headers=owner_headers
    ).status_code == 404


def test_repository_rejects_malicious_zip_with_bad_request(tmp_path):
    client = _client(tmp_path)
    headers = _register(client)

    response = client.post(
        "/api/repositories/analyses",
        headers=headers,
        json=_zip_body([("../outside.py", 'SECRET_KEY = "must-not-extract"')]),
    )

    assert response.status_code == 400
    assert "ZIP" in response.json()["detail"]


def test_repository_rejects_zip_above_configured_limit(tmp_path):
    client = _client(tmp_path, max_repo_zip_bytes=10)
    headers = _register(client)

    response = client.post(
        "/api/repositories/analyses",
        headers=headers,
        json=_zip_body([("app.py", "x" * 100)]),
    )

    assert response.status_code == 413


def test_repository_request_body_limit_uses_configured_zip_size(tmp_path):
    client = _client(tmp_path, max_repo_zip_bytes=10)

    response = client.post(
        "/api/repositories/analyses",
        content=b"x" * 5_000,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "ZIP" in response.json()["detail"]


def test_repository_upload_rate_limit_is_five_per_user_per_hour(tmp_path):
    client = _client(tmp_path, rate_limit=True)
    headers = _register(client)
    body = _zip_body()

    statuses = [
        client.post(
            "/api/repositories/analyses",
            headers=headers,
            json=body,
        ).status_code
        for _ in range(6)
    ]

    assert statuses == [201, 201, 201, 201, 201, 429]


def test_repository_history_reports_truncated_findings(tmp_path, monkeypatch):
    client = _client(tmp_path)
    headers = _register(client)
    findings = []
    for index in range(21):
        locations = list(range(1, 26)) if index == 0 else [index + 1]
        findings.append(
            {
                "id": f"rule-{index}",
                "title": f"Regra {index}",
                "severity": "Crítica",
                "cwe": "CWE-89",
                "owaspId": "A05",
                "owaspName": "Injeção",
                "description": "Achado de teste.",
                "recommendation": "Corrija a entrada.",
                "impact": "Risco de teste.",
                "prevention": "Valide a entrada.",
                "locations": locations,
                "evidence": ["linha de teste"] * len(locations),
            }
        )
    report = {
        "findingsByFile": {"src/app.py": findings},
        "countsBySeverity": {"Crítica": 45},
        "countsByOwasp": {"A05 - Injeção": 45},
        "filesAnalyzed": ["src/app.py"],
        "ignoredFiles": [],
        "filesNotAnalyzed": [],
        "partial": False,
        "durationSeconds": 0.1,
    }
    monkeypatch.setattr("app.service.scan_repository", lambda _path: report)

    response = client.post(
        "/api/repositories/analyses",
        headers=headers,
        json=_zip_body(),
    )

    assert response.status_code == 201, response.text
    result = response.json()
    assert len(result["findingsByFile"]["src/app.py"]) == 20
    assert result["findingsTruncated"] is True
    assert result["truncatedFindingsCount"] == 1
    assert result["truncatedOccurrencesCount"] == 6
    first_finding = result["findingsByFile"]["src/app.py"][0]
    assert len(first_finding["locations"]) == 20
    assert len(first_finding["evidence"]) == 20
    assert len(json.dumps(result, ensure_ascii=False).encode("utf-8")) < 8_000_000
