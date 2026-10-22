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
    safe_on_line: re.Pattern[str] | None = None


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
                safe_on_line=re.compile(safe, _FLAGS) if safe else None,
            )
        )
    return rules


RULES: list[Rule] = _load_rules()

# Regra sintética para manifestos de dependência (requirements.txt / package.json).
DEPENDENCY_RULE = Rule(
    id="unlocked-dependency",
    title="Dependência sem versão fixada",
    severity="Média",
    cwe="CWE-1104",
    owasp_id="A03",
    owasp_name="Falhas na cadeia de suprimentos",
    expression=re.compile(r"^"),
    description="Uma dependência não especifica uma versão verificável.",
    recommendation=(
        "Fixe versões revisadas, mantenha lockfile e use ferramenta SCA para "
        "verificar CVEs e dependências transitivas."
    ),
    impact=(
        "Instalações em momentos diferentes podem resolver versões distintas, "
        "inclusive versões comprometidas."
    ),
    prevention=(
        "Gere e revise lockfiles, monitore avisos de segurança e valide "
        "dependências em CI. Esta regra não verifica CVEs."
    ),
)

# Total de regras executadas: as regex por linha + a regra de manifesto.
RULE_COUNT = len(RULES) + 1

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
        for index, line in enumerate(re.split(r"\r?\n", source)):
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

    for index, line in enumerate(re.split(r"\r?\n", source)):
        if deadline is not None and time.perf_counter() > deadline:
            raise ScanTimeout()
        candidate = line[:max_line_chars]
        for rule in RULES:
            if not rule.expression.search(candidate):
                continue
            if rule.safe_on_line and rule.safe_on_line.search(candidate):
                continue
            add(rule, index + 1, line.strip()[:500])

    for rule, line, evidence in _scan_dependency_manifest(source, filename):
        add(rule, line, evidence)

    findings = sorted(grouped.values(), key=_sort_key)
    return ScanResult(findings=findings, rules_run=RULE_COUNT)
