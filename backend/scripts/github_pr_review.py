"""Run AuraScanner against changed GitHub PR files and add inline review comments."""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanner import ScanTimeout, scan_source  # noqa: E402

API_ROOT = "https://api.github.com"
MAX_SOURCE_BYTES = 1_000_000
MAX_LINE_CHARS = 1000
SCAN_TIMEOUT_SECONDS = 10
SUPPORTED_SUFFIXES = {
    ".c",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".json",
    ".php",
    ".py",
    ".rb",
    ".ts",
    ".tsx",
    ".txt",
}
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines_from_patch(patch: str | None) -> set[int]:
    """Return new-file line numbers introduced by a unified diff."""
    added: set[int] = set()
    new_line: int | None = None

    for line in patch.splitlines() if isinstance(patch, str) else ():
        match = HUNK_HEADER.match(line)
        if match:
            new_line = int(match.group(1))
            continue
        if new_line is None or line.startswith("\\"):
            continue
        if line.startswith("+"):
            added.add(new_line)
            new_line += 1
        elif line.startswith("-"):
            continue
        elif line.startswith(" "):
            new_line += 1

    return added


def comments_for_findings(
    path: str, findings: list[dict[str, Any]], changed_lines: set[int]
) -> list[dict[str, Any]]:
    """Build GitHub inline comments only for findings on added diff lines."""
    by_line: dict[int, list[str]] = {}
    for finding in findings:
        for index, line_number in enumerate(finding["locations"]):
            if line_number not in changed_lines:
                continue
            evidence = finding["evidence"][index] if index < len(finding["evidence"]) else ""
            code_fence = "`" * max(
                3,
                max((len(match.group()) for match in re.finditer(r"`+", evidence)), default=0)
                + 1,
            )
            body = (
                f"**{finding['severity']} — {finding['title']}** "
                f"({finding['cwe']}, {finding['owaspId']}:2025)\n\n"
                f"{finding['description']}\n\n"
                f"**Recomendação:** {finding['recommendation']}\n\n"
                f"{code_fence}text\n{evidence[:500]}\n{code_fence}\n\n"
                "_Achado heurístico do AuraScanner; confirme no contexto do projeto._"
            )
            by_line.setdefault(line_number, []).append(body)

    return [
        {
            "path": path,
            "line": line_number,
            "side": "RIGHT",
            "body": "\n\n---\n\n".join(bodies),
        }
        for line_number, bodies in sorted(by_line.items())
    ]


def render_step_summary(
    files_scanned: int,
    files_skipped: int,
    occurrences_by_severity: dict[str, int],
    comments_published: int,
    elapsed_seconds: float,
) -> str:
    total_occurrences = sum(occurrences_by_severity.values())
    lines = [
        "## AuraScanner · revisão de segurança",
        "",
        f"- **Arquivos analisados:** {files_scanned}",
        f"- **Ocorrências sinalizadas:** {total_occurrences}",
        f"- **Comentários inline publicados:** {comments_published}",
        f"- **Duração:** {elapsed_seconds:.1f} s",
    ]
    if files_skipped:
        lines.extend(
            [
                f"- **Arquivos não analisados:** {files_skipped} "
                "(limite de tamanho, formato, diff indisponível ou tempo excedido)",
            ]
        )
    if total_occurrences:
        lines.extend(
            [
                "",
                "| Severidade | Ocorrências |",
                "|---|---:|",
                *[
                    f"| {severity} | {occurrences_by_severity[severity]} |"
                    for severity in ("Crítica", "Alta", "Média", "Baixa")
                    if occurrences_by_severity[severity]
                ],
            ]
        )
    else:
        lines.extend(["", "Nenhum padrão foi sinalizado nos arquivos e linhas analisados."])
    lines.extend(
        [
            "",
            "> Resultado heurístico e não bloqueante. A ausência de alertas não "
            "comprova que o código esteja livre de vulnerabilidades.",
            "",
        ]
    )
    return "\n".join(lines)


def _api_request(token: str, endpoint: str) -> Any:
    request = Request(
        f"{API_ROOT}{endpoint}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AuraScanner",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"GitHub API respondeu HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Não foi possível acessar a API do GitHub: {exc}") from exc


def _api_post(token: str, endpoint: str, payload: dict[str, Any]) -> Any:
    request = Request(
        f"{API_ROOT}{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AuraScanner",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"GitHub API respondeu HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Não foi possível acessar a API do GitHub: {exc}") from exc


def _changed_files(token: str, repository: str, pull_number: int) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    page = 1
    while True:
        response = _api_request(
            token,
            f"/repos/{repository}/pulls/{pull_number}/files?per_page=100&page={page}",
        )
        if not isinstance(response, list):
            raise RuntimeError("A API do GitHub retornou uma lista de arquivos inválida.")
        files.extend(response)
        if len(response) < 100:
            return files
        page += 1


def _file_source(
    token: str, repository: str, path: str, head_sha: str
) -> str | None:
    encoded_path = quote(path, safe="/")
    encoded_ref = quote(head_sha, safe="")
    response = _api_request(
        token, f"/repos/{repository}/contents/{encoded_path}?ref={encoded_ref}"
    )
    if not isinstance(response, dict) or response.get("encoding") != "base64":
        return None
    content = response.get("content")
    if not isinstance(content, str):
        print(f"Aviso: conteúdo inválido retornado para {path!r}; arquivo ignorado.")
        return None
    try:
        encoded_content = "".join(content.split())
        raw = base64.b64decode(encoded_content, validate=True)
        if len(raw) > MAX_SOURCE_BYTES:
            print(f"Aviso: arquivo {path!r} acima do limite de 1 MB; ignorado.")
            return None
        return raw.decode("utf-8-sig")
    except (KeyError, ValueError, UnicodeDecodeError):
        print(f"Aviso: arquivo {path!r} não é texto UTF-8 válido; ignorado.")
        return None


def run_review(
    token: str,
    repository: str,
    pull_number: int,
    head_sha: str,
    summary_path: str | None = None,
) -> int:
    started_at = __import__("time").perf_counter()
    review_comments: list[dict[str, Any]] = []
    files_scanned = 0
    files_skipped = 0
    occurrences_by_severity = {"Crítica": 0, "Alta": 0, "Média": 0, "Baixa": 0}

    for changed_file in _changed_files(token, repository, pull_number):
        path = changed_file.get("filename")
        if (
            not isinstance(path, str)
            or changed_file.get("status") == "removed"
            or Path(path).suffix.lower() not in SUPPORTED_SUFFIXES
        ):
            continue

        patch = changed_file.get("patch")
        if not isinstance(patch, str):
            print(f"Aviso: diff indisponível para {path!r}; arquivo ignorado.")
            files_skipped += 1
            continue
        changed_lines = added_lines_from_patch(patch)
        if not changed_lines:
            continue
        source = _file_source(token, repository, path, head_sha)
        if source is None:
            files_skipped += 1
            continue

        files_scanned += 1
        try:
            result = scan_source(
                source,
                path,
                max_line_chars=MAX_LINE_CHARS,
                time_budget_seconds=SCAN_TIMEOUT_SECONDS,
            )
        except ScanTimeout:
            print(f"Aviso: análise de {path!r} excedeu o limite de 10 segundos.")
            files_skipped += 1
            continue

        for finding in result.findings:
            occurrences_by_severity[finding.severity] += len(finding.locations)
        review_comments.extend(
            comments_for_findings(
                path,
                [finding.to_dict() for finding in result.findings],
                changed_lines,
            )
        )

    print(f"AuraScanner: {len(review_comments)} comentário(s) em linhas adicionadas.")
    if review_comments:
        for start in range(0, len(review_comments), 50):
            comment_batch = review_comments[start : start + 50]
            _api_post(
                token,
                f"/repos/{repository}/pulls/{pull_number}/reviews",
                {
                    "commit_id": head_sha,
                    "event": "COMMENT",
                    "body": (
                        f"AuraScanner encontrou {sum(occurrences_by_severity.values())} "
                        "ocorrência(s) nas linhas adicionadas. Revise os comentários "
                        "antes do merge. Esta verificação é informativa e não bloqueia o pipeline."
                    ),
                    "comments": comment_batch,
                },
            )
    if summary_path:
        summary = render_step_summary(
            files_scanned,
            files_skipped,
            occurrences_by_severity,
            len(review_comments),
            __import__("time").perf_counter() - started_at,
        )
        Path(summary_path).write_text(summary, encoding="utf-8")
    return len(review_comments)


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    head_sha = os.environ.get("PR_HEAD_SHA", "")
    raw_pull_number = os.environ.get("PR_NUMBER", "")
    if not token or not repository or not head_sha or not raw_pull_number.isdigit():
        raise SystemExit(
            "Defina GITHUB_TOKEN, GITHUB_REPOSITORY, PR_NUMBER e PR_HEAD_SHA."
        )

    run_review(
        token,
        repository,
        int(raw_pull_number),
        head_sha,
        os.environ.get("GITHUB_STEP_SUMMARY"),
    )


if __name__ == "__main__":
    main()
