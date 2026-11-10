"""API FastAPI do VibeCheck.

Execução:  uvicorn app.main:app --reload

Rotas (todas sob /api):
  GET    /api/health                          verificação de saúde
  GET    /api/rules                           regras disponíveis (metadados)

  POST   /api/auth/register                   cria conta e já abre sessão
  POST   /api/auth/login                      abre sessão
  POST   /api/auth/logout                     encerra a sessão atual
  GET    /api/auth/me                         usuário da sessão atual
  POST   /api/auth/password-reset             envia link de recuperação por e-mail
  POST   /api/auth/password-reset/confirm     define a nova senha

  POST   /api/analyses                        executa uma análise e grava no histórico
  GET    /api/analyses                        histórico do usuário (mais recentes primeiro)
  GET    /api/analyses/{id}                   uma análise do histórico
  DELETE /api/analyses                        limpa o histórico do usuário

Rotas protegidas exigem  Authorization: Bearer <token>  (token devolvido por
register/login).

Obs.: este módulo NÃO usa `from __future__ import annotations` de propósito: o
FastAPI precisa resolver aliases `Annotated` definidos dentro de create_app().
"""

import logging
from typing import Annotated, Any

from fastapi import BackgroundTasks, Depends, FastAPI, Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .auth import AuthManager
from .config import Settings, get_settings
from .db import Database
from .errors import ApiError
from .mailer import Mailer, build_mailer
from .ratelimit import RateLimiter
from .scanner import RULES
from .schemas import (
    AnalysisOut,
    AnalysisRequest,
    AuthOut,
    Credentials,
    HealthOut,
    MessageOut,
    ResetConfirm,
    ResetRequest,
    RuleOut,
    UserOut,
)
from .service import run_analysis
from .storage import AnalysisStore

logger = logging.getLogger("vibecheck")

# JSON com escapes (\uXXXX) pode ser bem maior que o código-fonte original.
_BODY_LIMIT_FACTOR = 6
DEMO_EMAIL = "demo@vibecheck.dev"
DEMO_PASSWORD = "vibecheck2026"


class _NoLimit:
    def hit(self, key: str) -> bool:
        return True

    def reset(self, key: str) -> None:
        return None


def _limiter(enabled: bool, max_events: int, window_seconds: int) -> RateLimiter | _NoLimit:
    return RateLimiter(max_events, window_seconds) if enabled else _NoLimit()


def _client_ip(request: Request) -> str:
    # Atrás de proxy reverso, request.client é o proxy. Configure o uvicorn com
    # --proxy-headers / --forwarded-allow-ips para obter o IP real do cliente.
    return request.client.host if request.client else "desconhecido"


def create_app(settings: Settings | None = None, mailer: Mailer | None = None) -> FastAPI:
    settings = settings or get_settings()
    mailer = mailer or build_mailer(settings)
    db = Database(settings)
    store = AnalysisStore(db, max_history=settings.max_history)
    auth = AuthManager(
        db,
        session_ttl_seconds=settings.session_ttl_hours * 3600,
        reset_ttl_seconds=settings.reset_ttl_minutes * 60,
    )
    max_body = settings.max_source_bytes * _BODY_LIMIT_FACTOR + 4096

    on = settings.rate_limit_enabled
    login_limit = _limiter(on, 10, 15 * 60)  # por IP + e-mail
    register_limit = _limiter(on, 10, 60 * 60)  # por IP
    reset_limit = _limiter(on, 5, 60 * 60)  # por IP
    analysis_limit = _limiter(on, 30, 60)  # por usuário (a análise usa CPU)

    def too_many(window_seconds: int) -> ApiError:
        return ApiError(
            429,
            "Muitas tentativas. Aguarde alguns minutos e tente novamente.",
            headers={"Retry-After": str(window_seconds)},
        )

    if settings.seed_demo_user:
        try:
            auth.register(DEMO_EMAIL, DEMO_PASSWORD)
            logger.warning(
                "Usuário de demonstração criado (%s / %s). Credencial pública: "
                "não use em produção.",
                DEMO_EMAIL,
                DEMO_PASSWORD,
            )
        except ApiError:
            pass  # já existe

    app = FastAPI(title="VibeCheck API", version="0.2.0")

    @app.middleware("http")
    async def limit_body_size(request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.method == "POST":
            length = request.headers.get("content-length")
            if length is None:
                return JSONResponse(
                    {"detail": "Cabeçalho Content-Length é obrigatório."}, status_code=411
                )
            if not length.isdigit() or int(length) > max_body:
                return JSONResponse(
                    {"detail": "O código excede o limite de 1 MB."}, status_code=413
                )
        return await call_next(request)

    # Adicionado por último = middleware mais externo, para que até as respostas
    # 411/413 do limitador de corpo levem os cabeçalhos CORS.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
    )

    @app.exception_handler(ApiError)
    async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            {"detail": exc.message}, status_code=exc.status_code, headers=exc.headers
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, __: RequestValidationError) -> JSONResponse:
        # O frontend exibe `detail` como texto; evita devolver a lista crua do Pydantic.
        return JSONResponse(
            {"detail": "Requisição inválida. Verifique os campos enviados."},
            status_code=422,
        )

    # ---------- dependências ----------
    # Funções síncronas rodam no threadpool: scrypt, análise (CPU) e SQLite não
    # bloqueiam o event loop.

    def bearer_token(authorization: Annotated[str | None, Header()] = None) -> str:
        if not authorization or authorization[:7].lower() != "bearer ":
            raise ApiError(
                401, "Faça login para continuar.", headers={"WWW-Authenticate": "Bearer"}
            )
        return authorization[7:].strip()

    Token = Annotated[str, Depends(bearer_token)]

    def current_user(token: Token) -> dict[str, Any]:
        user = auth.user_for_token(token)
        if user is None:
            raise ApiError(
                401,
                "Sessão expirada. Entre novamente.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user

    User = Annotated[dict[str, Any], Depends(current_user)]

    # ---------- geral ----------

    @app.get("/api/health", response_model=HealthOut)
    def health() -> dict[str, object]:
        return {"status": "ok", "rules": len(RULES)}

    @app.get("/api/rules", response_model=list[RuleOut])
    def list_rules() -> list[dict[str, str]]:
        return [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "cwe": rule.cwe,
                "owaspId": rule.owasp_id,
                "owaspName": rule.owasp_name,
                "description": rule.description,
                "recommendation": rule.recommendation,
                "impact": rule.impact,
                "prevention": rule.prevention,
                "confidence": rule.confidence,
            }
            for rule in RULES
        ]

    # ---------- autenticação ----------

    @app.post("/api/auth/register", response_model=AuthOut, status_code=201)
    def register(body: Credentials, request: Request) -> dict[str, Any]:
        if not register_limit.hit(_client_ip(request)):
            raise too_many(3600)
        user, token = auth.register(body.email, body.password)
        return {"token": token, "user": user}

    @app.post("/api/auth/login", response_model=AuthOut)
    def login(body: Credentials, request: Request) -> dict[str, Any]:
        key = f"{_client_ip(request)}|{body.email.strip().lower()}"
        if not login_limit.hit(key):
            raise too_many(15 * 60)
        user, token = auth.login(body.email, body.password)
        login_limit.reset(key)
        return {"token": token, "user": user}

    @app.post("/api/auth/logout", status_code=204)
    def logout(token: Token) -> Response:
        auth.logout(token)
        return Response(status_code=204)

    @app.get("/api/auth/me", response_model=UserOut)
    def me(user: User) -> dict[str, Any]:
        return user

    @app.post("/api/auth/password-reset", response_model=MessageOut, status_code=202)
    def request_password_reset(
        body: ResetRequest, request: Request, background: BackgroundTasks
    ) -> dict[str, str]:
        if not reset_limit.hit(_client_ip(request)):
            raise too_many(3600)
        created = auth.create_reset_token(body.email)
        if created is not None:
            email, token = created
            # O token vai no fragmento (#), que o navegador não envia a servidores.
            url = f"{settings.frontend_url.rstrip('/')}/#reset_token={token}"

            def send() -> None:
                try:
                    mailer.send_password_reset(email, url)
                except Exception:  # noqa: BLE001 - não pode derrubar a resposta
                    logger.exception("Falha ao enviar e-mail de recuperação")

            # Envio após a resposta: o tempo de resposta não revela se o e-mail existe.
            background.add_task(send)
        # Mesma resposta exista a conta ou não (evita enumeração de usuários).
        return {
            "message": "Se o e-mail estiver cadastrado, enviaremos as instruções de recuperação."
        }

    @app.post("/api/auth/password-reset/confirm", status_code=204)
    def confirm_password_reset(body: ResetConfirm, request: Request) -> Response:
        if not reset_limit.hit(f"confirm|{_client_ip(request)}"):
            raise too_many(3600)
        auth.reset_password(body.token, body.new_password)
        return Response(status_code=204)

    # ---------- análises ----------

    @app.post("/api/analyses", response_model=AnalysisOut, status_code=201)
    def create_analysis(body: AnalysisRequest, user: User) -> dict[str, Any]:
        if not analysis_limit.hit(user["id"]):
            raise too_many(60)
        analysis = run_analysis(
            body.filename,
            body.source,
            max_source_bytes=settings.max_source_bytes,
            max_line_chars=settings.max_line_chars,
            scan_timeout_seconds=settings.scan_timeout_seconds,
        )
        store.save(user["id"], analysis)
        return analysis

    @app.get("/api/analyses", response_model=list[AnalysisOut])
    def list_analyses(user: User) -> list[dict[str, Any]]:
        return store.list(user["id"])

    @app.get("/api/analyses/{analysis_id}", response_model=AnalysisOut)
    def get_analysis(analysis_id: str, user: User) -> dict[str, Any]:
        analysis = store.get(user["id"], analysis_id)
        if analysis is None:
            raise ApiError(404, "Análise não encontrada.")
        return analysis

    @app.delete("/api/analyses", status_code=204)
    def clear_analyses(user: User) -> Response:
        store.clear(user["id"])
        return Response(status_code=204)

    return app


app = create_app()
