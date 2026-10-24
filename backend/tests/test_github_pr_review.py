from scripts import github_pr_review
from scripts.github_pr_review import added_lines_from_patch, comments_for_findings


def test_added_lines_from_patch_tracks_new_file_line_numbers():
    patch = (
        "@@ -1,3 +1,4 @@\n"
        " context\n"
        "-old line\n"
        "+new line\n"
        "+another new line\n"
        "@@ -10,2 +11,2 @@\n"
        "-removed\n"
        "+replacement\n"
    )

    assert added_lines_from_patch(patch) == {2, 3, 11}


def test_added_lines_can_start_with_diff_marker_characters():
    patch = "@@ -0,0 +1,2 @@\n++++ content beginning with plus\n+--- content beginning with minus\n"

    assert added_lines_from_patch(patch) == {1, 2}


def test_comments_are_limited_to_added_lines_and_grouped_by_line():
    findings = [
        {
            "id": "hardcoded-secret",
            "title": "Credencial fixa no código",
            "severity": "Crítica",
            "cwe": "CWE-798",
            "owaspId": "A04",
            "description": "Um segredo parece estar fixo.",
            "recommendation": "Use uma variável de ambiente.",
            "locations": [4, 8],
            "evidence": ['password = "demo-secret"', "secret = 'another-secret'"],
        },
        {
            "id": "sql-injection",
            "title": "Possível SQL Injection",
            "severity": "Crítica",
            "cwe": "CWE-89",
            "owaspId": "A05",
            "description": "Consulta dinâmica.",
            "recommendation": "Use parâmetros.",
            "locations": [4],
            "evidence": ['query = "SELECT " + user_input'],
        },
    ]

    comments = comments_for_findings("src/app.py", findings, {4})

    assert len(comments) == 1
    assert comments[0]["path"] == "src/app.py"
    assert comments[0]["line"] == 4
    assert comments[0]["side"] == "RIGHT"
    assert "Credencial fixa no código" in comments[0]["body"]
    assert "Possível SQL Injection" in comments[0]["body"]
    assert "another-secret" not in comments[0]["body"]


def test_missing_patch_has_no_changed_lines():
    assert added_lines_from_patch(None) == set()
    assert added_lines_from_patch("") == set()


def test_run_review_posts_only_findings_on_added_lines(monkeypatch):
    source = 'password = "demo-secret-value"\nprint("hello")\n'
    posted = []
    monkeypatch.setattr(
        github_pr_review,
        "_changed_files",
        lambda token, repository, pull_number: [
            {
                "filename": "app.py",
                "status": "modified",
                "patch": "@@ -1,2 +1,2 @@\n-password = old_value\n+"
                + source.splitlines()[0]
                + '\n print("hello")\n',
            }
        ],
    )
    monkeypatch.setattr(
        github_pr_review,
        "_file_source",
        lambda token, repository, path, head_sha: source,
    )
    monkeypatch.setattr(
        github_pr_review,
        "_api_post",
        lambda token, endpoint, payload: posted.append((endpoint, payload)),
    )

    count = github_pr_review.run_review("token", "owner/repo", 7, "head-sha")

    assert count == 1
    assert len(posted) == 1
    endpoint, payload = posted[0]
    assert endpoint == "/repos/owner/repo/pulls/7/reviews"
    assert payload["commit_id"] == "head-sha"
    assert payload["comments"][0]["line"] == 1
    assert "Credencial fixa no código" in payload["comments"][0]["body"]


def test_file_source_decodes_wrapped_base64_content(monkeypatch):
    content = "cGFzc3dvcmQ="
    monkeypatch.setattr(
        github_pr_review,
        "_api_request",
        lambda token, endpoint: {"encoding": "base64", "content": f"{content}\n"},
    )

    assert github_pr_review._file_source("token", "owner/repo", "app.py", "sha") == "password"
