"""Modelos da API. JSON em camelCase, idêntico às interfaces de ``src/types.ts``."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

Severity = Literal["Crítica", "Alta", "Média", "Baixa"]


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


class AnalysisOut(CamelModel):
    id: str
    filename: str
    language: str
    lines_analyzed: int
    created_at: str
    duration_ms: int
    findings: list[FindingOut]
    rules_run: int


class RuleOut(CamelModel):
    id: str
    title: str
    severity: Severity
    cwe: str
    owasp_id: str
    owasp_name: str


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
