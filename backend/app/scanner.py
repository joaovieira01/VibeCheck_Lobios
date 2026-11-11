"""Analisador estático heurístico.

Porte fiel de ``src/services/scanner.ts`` do frontend. As regras ficam em
``rules.json`` (extraídas do TypeScript, com a mesma regex), então frontend e
backend produzem os mesmos achados para a mesma entrada.

As regras são heurísticas por linha: não executam o código e não substituem uma
auditoria, SAST/DAST ou análise de dependências (SCA).
"""

from __future__ import annotations

import json
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# \w e \b em JavaScript são ASCII; re.ASCII mantém o mesmo comportamento.
_FLAGS = re.IGNORECASE | re.ASCII

SEVERITY_ORDER = {"Crítica": 0, "Alta": 1, "Média": 2, "Baixa": 3}

DEFAULT_MAX_LINE_CHARS = 1000


class ScanTimeout(Exception):
    """A análise ultrapassou o orçamento de tempo."""


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    cwe: str
    owasp_id: str
    owasp_name: str
    expression: re.Pattern[str]
    description: str
    recommendation: str
    impact: str
    prevention: str
    confidence: str
    safe_on_line: re.Pattern[str] | None = None
    safe_on_context: re.Pattern[str] | None = None
    context_lines: int = 0
    required_context: re.Pattern[str] | None = None
    required_context_lines: int = 0
    manifest_only: bool = False


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    cwe: str
    owasp_id: str
    owasp_name: str
    description: str
    recommendation: str
    impact: str
    prevention: str
    locations: list[int] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Formato camelCase esperado pelo frontend (interface ``Finding``)."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "owaspId": self.owasp_id,
            "owaspName": self.owasp_name,
            "description": self.description,
            "recommendation": self.recommendation,
            "impact": self.impact,
            "prevention": self.prevention,
            "locations": self.locations,
            "evidence": self.evidence,
        }


@dataclass
class ScanResult:
    findings: list[Finding]
    rules_run: int


def _load_rules() -> list[Rule]:
    path = Path(__file__).with_name("rules.json")
    raw_rules = json.loads(path.read_text(encoding="utf-8"))
    rules: list[Rule] = []
    for item in raw_rules:
        safe = item.get("safePattern")
        safe_context = item.get("safeContextPattern")
        rules.append(
            Rule(
                id=item["id"],
                title=item["title"],
                severity=item["severity"],
                cwe=item["cwe"],
                owasp_id=item["owaspId"],
                owasp_name=item["owaspName"],
                expression=re.compile(item["pattern"], _FLAGS),
                description=item["description"],
                recommendation=item["recommendation"],
                impact=item["impact"],
                prevention=item["prevention"],
                confidence=item["confidence"],
                safe_on_line=re.compile(safe, _FLAGS) if safe else None,
                safe_on_context=(
                    re.compile(safe_context, _FLAGS) if safe_context else None
                ),
                context_lines=item.get("contextLines", 0),
                required_context=(
                    re.compile(item["requiredContextPattern"], _FLAGS)
                    if item.get("requiredContextPattern")
                    else None
                ),
                required_context_lines=item.get("requiredContextLines", 0),
                manifest_only=item.get("manifestOnly", False),
            )
        )
    return rules


RULES: list[Rule] = _load_rules()
RULES_BY_ID = {rule.id: rule for rule in RULES}
SCANNABLE_RULES = [rule for rule in RULES if not rule.manifest_only]
DEPENDENCY_RULE = RULES_BY_ID["unlocked-dependency"]
RULE_COUNT = len(RULES)

_REQUIREMENT_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?:#.*)?$")
_LOOSE_JSON_VERSION = re.compile(r"[\"']([@a-zA-Z0-9/_.-]+)[\"']\s*:\s*[\"'](?:\*|latest)[\"']")


def _line_of(source: str, index: int) -> int:
    return source.count("\n", 0, max(index, 0)) + 1


def _scan_dependency_manifest(
    source: str, filename: str
) -> list[tuple[Rule, int, str]]:
    name = filename.lower().replace("\\", "/").split("/")[-1]
    hits: list[tuple[Rule, int, str]] = []

    if name == "requirements.txt":
        lines = re.split(r"\r?\n", source)
        for index, line in enumerate(lines):
            trimmed = line.strip()
            if (
                _REQUIREMENT_LINE.match(trimmed)
                and not trimmed.startswith("#")
                and not trimmed.startswith("-")
            ):
                hits.append((DEPENDENCY_RULE, index + 1, trimmed))

    if name == "package.json":
        try:
            manifest = json.loads(source)
        except ValueError:
            for match in _LOOSE_JSON_VERSION.finditer(source):
                hits.append(
                    (DEPENDENCY_RULE, _line_of(source, match.start()), match.group(0))
                )
        else:
            if isinstance(manifest, dict):
                for group in ("dependencies", "devDependencies", "optionalDependencies"):
                    dependencies = manifest.get(group)
                    if not isinstance(dependencies, dict):
                        continue
                    for dep_name, version in dependencies.items():
                        unlocked = version in ("*", "latest") or (
                            isinstance(version, str) and version.strip() == ""
                        )
                        if not unlocked:
                            continue
                        position = source.find(f'"{dep_name}"')
                        hits.append(
                            (
                                DEPENDENCY_RULE,
                                _line_of(source, position) if position >= 0 else 1,
                                f'"{dep_name}": "{version}"',
                            )
                        )
    return hits


def _mask_comments_and_block_strings(source: str, filename: str) -> str:
    chars = list(source)
    python = filename.lower().endswith((".py", ".pyi"))

    def mask(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] not in "\r\n":
                chars[position] = " "

    index = 0
    while index < len(source):
        char = source[index]
        if (
            python
            and char in ("'", '"')
            and source[index : index + 3] == char * 3
        ):
            end = source.find(char * 3, index + 3)
            block_end = len(source) if end < 0 else end + 3
            mask(index, block_end)
            index = block_end
            continue
        if not python and char == "/" and source[index + 1 : index + 2] == "/":
            end = source.find("\n", index)
            comment_end = len(source) if end < 0 else end
            mask(index, comment_end)
            index = comment_end
            continue
        if not python and source[index : index + 2] == "/*":
            end = source.find("*/", index + 2)
            comment_end = len(source) if end < 0 else end + 2
            mask(index, comment_end)
            index = comment_end
            continue
        if python and char == "#":
            end = source.find("\n", index)
            comment_end = len(source) if end < 0 else end
            mask(index, comment_end)
            index = comment_end
            continue
        if char in ("'", '"') or (not python and char == "`"):
            quote = char
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        index += 1
    return "".join(chars)


_AUTHENTICATION_SIGNAL = re.compile(
    r"\b(?:Depends\s*\(|login_required|permission_classes|jwt_required|"
    r"requires_auth|authenticated_?user|current_?user|user\s*:\s*AuthenticatedUser\b|"
    r"request\.user(?:\.is_authenticated)?|"
    r"req\.user\b|isAuthenticated|"
    r"auth(?:entication)?Middleware|requireAuth|require_auth|"
    r"passport\.authenticate|LoginRequiredMixin|PermissionRequiredMixin|"
    r"IsAuthenticated|authenticate\w*|authorize\w*|auth\b)\b",
    _FLAGS,
)
_DESTRUCTIVE_OPERATION = re.compile(
    r"\b(?:delete_one|deleteMany|delete|drop|clear|update_one|updateMany)\s*\(",
    _FLAGS,
)
_AUTHENTICATED_TYPE_ALIAS = re.compile(
    r"^\s*(?:type\s+)?([A-Za-z_]\w*)\s*=\s*Annotated\s*\[[\s\S]{0,250}?\bDepends\s*\(",
    re.MULTILINE | re.IGNORECASE | re.ASCII,
)


def _missing_authentication_hits(
    lines: list[str], rule: Rule, filename: str
) -> list[tuple[int, str]]:
    python = filename.lower().endswith((".py", ".pyi"))
    hits: list[tuple[int, str]] = []
    handled_operations: set[int] = set()
    authenticated_types = _AUTHENTICATED_TYPE_ALIAS.findall("\n".join(lines))
    authenticated_parameter = (
        re.compile(
            rf"\b\w+\s*:\s*(?:{'|'.join(re.escape(name) for name in authenticated_types)})\b",
            _FLAGS,
        )
        if authenticated_types
        else None
    )

    def has_authentication_signal(context: str) -> bool:
        return bool(
            _AUTHENTICATION_SIGNAL.search(context)
            or (
                authenticated_parameter
                and authenticated_parameter.search(context)
            )
        )

    def add_hit(index: int) -> None:
        if all(line_number != index + 1 for line_number, _ in hits):
            hits.append((index + 1, lines[index].strip()[:500]))

    if python:
        route_decorator = re.compile(
            r"^\s*@(?:[\w.]+\.(?:delete|put|patch)\s*\(|"
            r"[\w.]+\.route\s*\(|"
            r"[\w.]*require_http_methods\s*\([^)]*(?:DELETE|PUT|PATCH)|"
            r"[\w.]*api_view\s*\([^)]*(?:DELETE|PUT|PATCH))",
            _FLAGS,
        )
        destructive_route_decorator = re.compile(
            r"^\s*@(?:[\w.]+\.(?:delete|put|patch)\s*\(|"
            r"[\w.]+\.route\s*\([^)]*methods\s*=\s*\[[^\]]*(?:DELETE|PUT|PATCH)|"
            r"[\w.]*require_http_methods\s*\([^)]*(?:DELETE|PUT|PATCH)|"
            r"[\w.]*api_view\s*\([^)]*(?:DELETE|PUT|PATCH))",
            _FLAGS,
        )
        function_line = re.compile(r"^\s*(?:async\s+)?def\s+\w+\s*\(")
        for index, line in enumerate(lines):
            django_mutation_method = re.match(
                r"^\s*(?:async\s+)?def\s+(?:delete|destroy|remove|update|partial_update)\w*\s*\(",
                line,
                _FLAGS,
            ) is not None
            is_django_handler = function_line.search(line) is not None and any(
                re.search(
                    r"""request\.method\s*==?\s*["'](?:DELETE|PUT|PATCH)["']""",
                    body_line,
                    _FLAGS,
                )
                for body_line in lines[index + 1 : index + 12]
            ) or function_line.search(line) is not None and django_mutation_method
            if not route_decorator.search(line) and not is_django_handler:
                continue

            handler = index
            if route_decorator.search(line):
                handler = next(
                    (
                        candidate
                        for candidate in range(index + 1, min(len(lines), index + 7))
                        if function_line.search(lines[candidate])
                    ),
                    -1,
                )
                if handler < 0:
                    continue

            indent = len(lines[handler]) - len(lines[handler].lstrip())
            end = len(lines)
            for cursor in range(handler + 1, len(lines)):
                next_definition = re.match(
                    r"^\s*(?:(?:async\s+)?def|class)\b", lines[cursor]
                )
                next_indent = len(lines[cursor]) - len(lines[cursor].lstrip())
                if next_definition and next_indent <= indent:
                    end = cursor
                    break
            has_mutation = any(
                _DESTRUCTIVE_OPERATION.search(body_line)
                for body_line in lines[handler:end]
            )
            if (
                not has_mutation
                and not is_django_handler
                and not destructive_route_decorator.search(line)
            ):
                continue
            for cursor in range(handler, end):
                if rule.expression.search(lines[cursor]):
                    handled_operations.add(cursor)
            handled_operations.add(index)
            context_start = index
            if route_decorator.search(line):
                while context_start > 0 and re.match(r"^\s*@", lines[context_start - 1]):
                    context_start -= 1
            else:
                context_start = max(0, index - 4)
            route_context = "\n".join(lines[context_start : min(end, handler + 12)])
            if not has_authentication_signal(route_context) and not (
                rule.safe_on_context and rule.safe_on_context.search(route_context)
            ):
                add_hit(handler)
    else:
        route_pattern = re.compile(
            r"^\s*(?:app|router|server|this\.router)\.(?:delete|put|patch)\s*\(",
            _FLAGS,
        )
        route_indices = [
            index for index, line in enumerate(lines) if route_pattern.search(line)
        ]
        global_auth = any(
            re.search(
                r"\b(?:app|server)\.use\s*\([^)]*(?:auth|authenticate|authorize|permission)",
                line,
                _FLAGS,
            )
            for line in lines
        )
        for route_number, start in enumerate(route_indices):
            end = (
                route_indices[route_number + 1]
                if route_number + 1 < len(route_indices)
                else len(lines)
            )
            handler = start
            if not re.search(r"=>|\bfunction\b", lines[start]):
                callback = next(
                    (
                        index
                        for index in range(start + 1, min(end, start + 8))
                        if re.search(r"=>|\bfunction\b", lines[index])
                    ),
                    -1,
                )
                if callback >= 0:
                    handler = callback
            for cursor in range(start, end):
                if rule.expression.search(lines[cursor]):
                    handled_operations.add(cursor)
            route_context = "\n".join(lines[start : min(end, handler + 8)])
            if (
                not global_auth
                and not has_authentication_signal(route_context)
                and not (
                    rule.safe_on_context
                    and rule.safe_on_context.search(route_context)
                )
            ):
                add_hit(handler)

    for index, line in enumerate(lines):
        if (
            index in handled_operations
            or not _DESTRUCTIVE_OPERATION.search(line)
            or not rule.expression.search(line)
        ):
            continue
        context_start = max(0, index - rule.context_lines)
        context_end = min(len(lines), index + rule.context_lines + 1)
        context = "\n".join(lines[context_start:context_end])
        if not _AUTHENTICATION_SIGNAL.search(context) and not (
            rule.safe_on_context and rule.safe_on_context.search(context)
        ):
            add_hit(index)
    return sorted(hits)


def _sort_key(finding: Finding) -> tuple[int, str]:
    # Aproxima localeCompare("pt-BR"): ignora acentos e caixa.
    decomposed = unicodedata.normalize("NFD", finding.title)
    plain = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return (SEVERITY_ORDER[finding.severity], plain.casefold())


def scan_source(
    source: str,
    filename: str,
    max_line_chars: int = DEFAULT_MAX_LINE_CHARS,
    time_budget_seconds: float | None = None,
) -> ScanResult:
    """Executa todas as regras sobre ``source``.

    ``max_line_chars`` trunca cada linha antes das regex e ``time_budget_seconds``
    aborta com ``ScanTimeout``: juntos limitam o custo de entradas hostis, já que
    algumas regex (herdadas do frontend) têm custo polinomial em linhas longas.
    """
    deadline = None if time_budget_seconds is None else time.perf_counter() + time_budget_seconds
    grouped: dict[str, Finding] = {}

    def add(rule: Rule, line: int, evidence: str) -> None:
        finding = grouped.get(rule.id)
        if finding is None:
            finding = Finding(
                id=rule.id,
                title=rule.title,
                severity=rule.severity,
                cwe=rule.cwe,
                owasp_id=rule.owasp_id,
                owasp_name=rule.owasp_name,
                description=rule.description,
                recommendation=rule.recommendation,
                impact=rule.impact,
                prevention=rule.prevention,
            )
            grouped[rule.id] = finding
        finding.locations.append(line)
        finding.evidence.append(evidence)

    lines = re.split(r"\r?\n", source)
    scannable_lines = re.split(
        r"\r?\n", _mask_comments_and_block_strings(source, filename)
    )
    for index, line in enumerate(lines):
        if deadline is not None and time.perf_counter() > deadline:
            raise ScanTimeout()
        candidate = scannable_lines[index][:max_line_chars]
        for rule in SCANNABLE_RULES:
            if rule.id == "missing-authentication":
                continue
            if not rule.expression.search(candidate):
                continue
            if rule.safe_on_line and rule.safe_on_line.search(candidate):
                continue
            if rule.safe_on_context or rule.required_context:
                context_radius = max(
                    rule.context_lines, rule.required_context_lines
                )
                context_start = max(0, index - context_radius)
                context_end = min(len(lines), index + context_radius + 1)
                context = "\n".join(scannable_lines[context_start:context_end])
                if (
                    rule.safe_on_context
                    and rule.safe_on_context.search(context)
                ):
                    continue
                if rule.required_context and not rule.required_context.search(context):
                    continue
            add(rule, index + 1, line.strip()[:500])

    missing_auth_candidate_lines = [
        line[:max_line_chars] for line in scannable_lines
    ]
    for line_number, _ in _missing_authentication_hits(
        missing_auth_candidate_lines,
        RULES_BY_ID["missing-authentication"],
        filename,
    ):
        add(
            RULES_BY_ID["missing-authentication"],
            line_number,
            lines[line_number - 1].strip()[:500],
        )

    for rule, line, evidence in _scan_dependency_manifest(source, filename):
        add(rule, line, evidence)

    findings = sorted(grouped.values(), key=_sort_key)
    return ScanResult(findings=findings, rules_run=RULE_COUNT)
