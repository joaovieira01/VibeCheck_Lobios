"""Modelos da API. JSON em camelCase, idêntico às interfaces de ``src/types.ts``."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

Severity = Literal["Crítica", "Alta", "Média", "Baixa"]
Confidence = Literal["alta", "média", "baixa"]


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


# ---------- análises ----------


class AnalysisRequest(CamelModel):
    filename: str = Field(min_length=1, max_length=255)
    # O limite de 1 MB é verificado em bytes UTF-8 no serviço, não em caracteres.
    source: str


class FindingOut(CamelModel):
    id: str
    title: str
    severity: Severity
    cwe: str
    owasp_id: str
    owasp_name: str
    description: str
    recommendation: str
    impact: str
    prevention: str
    locations: list[int]
    evidence: list[str]
    ai_verdict: Literal["confirmado", "falso_positivo", "incerto"] | None = None
    ai_confidence: float | None = Field(default=None, ge=0, le=1)
    ai_reason: str | None = Field(default=None, max_length=200)


class AIFindingOut(CamelModel):
    id: str = Field(max_length=80)
    title: str = Field(max_length=100)
    category: str = Field(max_length=30)
    line: int = Field(ge=1)
    severity: Literal["Alta"]
    origin: Literal["ia"]
    confidence: float = Field(ge=0, le=1)
    reason: str = Field(max_length=200)
    notice: str = Field(max_length=100)


class AISummaryOut(CamelModel):
    status: Literal["ativa", "desativada", "indisponivel"]
    calls: int = Field(ge=0)
    model: str | None = Field(default=None, max_length=100)
    error_code: Literal[
        "invalid_base_url",
        "network_error",
        "http_401",
        "http_403",
        "http_429",
        "http_5xx",
        "invalid_response",
        "response_too_large",
        "timeout_total",
        "calls_exhausted",
        "configuracao_invalida",
    ] | None = None


class AnalysisOut(CamelModel):
    id: str
    filename: str
    language: str
    lines_analyzed: int
    created_at: str
    duration_ms: int
    findings: list[FindingOut]
    rules_run: int
    ai_findings: list[AIFindingOut] = Field(default_factory=list, max_length=20)
    ai_summary: AISummaryOut | None = None


class RuleOut(CamelModel):
    id: str
    title: str
    severity: Severity
    cwe: str
    owasp_id: str
    owasp_name: str
    description: str
    recommendation: str
    impact: str
    prevention: str
    confidence: Confidence


class HealthOut(CamelModel):
    status: Literal["ok"]
    rules: int


# ---------- contas ----------


class Credentials(CamelModel):
    email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class UserOut(CamelModel):
    id: str
    email: str


class AuthOut(CamelModel):
    token: str
    user: UserOut


class ResetRequest(CamelModel):
    email: str = Field(min_length=1, max_length=254)


class ResetConfirm(CamelModel):
    token: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=1024)


class MessageOut(CamelModel):
    message: str
