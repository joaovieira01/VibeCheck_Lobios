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
  POST   /api/repositories/analyses           analisa um ZIP e grava o resultado
  GET    /api/repositories/analyses            histórico de repositórios
  GET    /api/repositories/analyses/{id}       detalhes de uma análise de repositório

Rotas protegidas exigem  Authorization: Bearer <token>  (token devolvido por
register/login).

Obs.: este módulo NÃO usa `from __future__ import annotations` de propósito: o
FastAPI precisa resolver aliases `Annotated` definidos dentro de create_app().
"""

import logging
from contextlib import asynccontextmanager
from threading import Lock
from typing import Annotated, Any, AsyncIterator

from fastapi import BackgroundTasks, Depends, FastAPI, Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

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
    RepositoryAnalysisOut,
    RepositoryAnalysisListOut,
    RepositoryAnalysisRequest,
    UserOut,
)
from .service import run_analysis, run_repository_analysis
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


def _validate_production_settings(settings: Settings) -> None:
    if settings.environment.strip().lower() != "production":
        return
    # A credencial da conta demo é pública e não pode ser ativa fora do dev.
    if settings.seed_demo_user:
        raise RuntimeError(
            "Em produção, VIBECHECK_SEED_DEMO_USER deve estar desativado."
        )
    # Uma origem curinga permite que qualquer site faça chamadas ao backend.
    if any("*" in origin for origin in settings.cors_origins):
        raise RuntimeError("Em produção, VIBECHECK_CORS_ORIGINS não pode conter '*'.")
    if settings.db_engine.strip().lower() == "mysql":
        # SQLite usa um arquivo local e não autentica com senha de banco.
        db_password = settings.db_password.strip()
        if not db_password or db_password == "CHANGE_THIS_PASSWORD":
            raise RuntimeError(
                "Em produção, defina uma senha de banco diferente da senha de exemplo."
            )


def ensure_state(application: FastAPI) -> None:
    if getattr(application.state, "_vibecheck_initialized", False):
        return

    with application.state._vibecheck_state_lock:
        if getattr(application.state, "_vibecheck_initialized", False):
            return

        settings: Settings = application.state._vibecheck_settings
        _validate_production_settings(settings)
        database = Database(settings)
        auth_manager = AuthManager(
            database,
            session_ttl_seconds=settings.session_ttl_hours * 3600,
            reset_ttl_seconds=settings.reset_ttl_minutes * 60,
        )
        store = AnalysisStore(database, max_history=settings.max_history)

        if settings.seed_demo_user:
            try:
                auth_manager.register(DEMO_EMAIL, DEMO_PASSWORD)
                logger.warning(
                    "Usuário de demonstração criado (%s). Use somente em desenvolvimento.",
                    DEMO_EMAIL,
                )
            except ApiError:
                pass  # a conta de demonstração já existe

        application.state.database = database
        application.state.auth = auth_manager
        application.state.store = store
        application.state._vibecheck_initialized = True


def create_app(settings: Settings | None = None, mailer: Mailer | None = None) -> FastAPI:
    settings = settings or get_settings()
    mailer = mailer or build_mailer(settings)
    max_body = settings.max_source_bytes * _BODY_LIMIT_FACTOR + 4096
    max_repo_body = ((settings.max_repo_zip_bytes + 2) // 3) * 4 + 4096

    on = settings.rate_limit_enabled
    login_ip_limit = _limiter(on, 20, 15 * 60)  # limita custo total por IP
    login_limit = _limiter(on, 5, 15 * 60)  # restringe tentativas por IP + e-mail
    register_limit = _limiter(on, 10, 60 * 60)  # por IP
    reset_limit = _limiter(on, 5, 60 * 60)  # por IP
    analysis_limit = _limiter(on, 30, 60)  # por usuário (a análise usa CPU)
    repository_analysis_limit = _limiter(on, 5, 60 * 60)  # por usuário

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        ensure_state(application)
        yield

    app = FastAPI(title="VibeCheck API", version="0.2.0", lifespan=lifespan)
    app.state._vibecheck_settings = settings
    app.state._vibecheck_state_lock = Lock()
    app.state._vibecheck_initialized = False

    def auth_manager() -> AuthManager:
        return app.state.auth

    def analysis_store() -> AnalysisStore:
        return app.state.store

    def too_many(window_seconds: int) -> ApiError:
        return ApiError(
            429,
            "Muitas tentativas. Aguarde alguns minutos e tente novamente.",
            headers={"Retry-After": str(window_seconds)},
        )

    @app.middleware("http")
    async def limit_body_size(request: Request, call_next):  # type: ignore[no-untyped-def]
        ensure_state(app)
        if request.method == "POST":
            is_repository_upload = (
                request.url.path.rstrip("/") == "/api/repositories/analyses"
            )
            body_limit = max_repo_body if is_repository_upload else max_body
            length = request.headers.get("content-length")
            if length is None:
                return JSONResponse(
                    {"detail": "Cabeçalho Content-Length é obrigatório."}, status_code=411
                )
            if not length.isdigit() or int(length) > body_limit:
                return JSONResponse(
                    {
                        "detail": (
                            "O arquivo ZIP excede o limite configurado."
                            if is_repository_upload
                            else "O código excede o limite de 1 MB."
                        )
                    },
                    status_code=413,
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
        user = auth_manager().user_for_token(token)
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
    def health(response: Response) -> dict[str, object]:
        try:
            with app.state.database.connect() as conn:
                conn.execute("SELECT 1").fetchone()
        except Exception:
            logger.exception("Falha na verificação de saúde do banco.")
            response.status_code = 503
            return {"status": "degraded", "rules": len(RULES)}
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
        user, token = auth_manager().register(body.email, body.password)
        return {"token": token, "user": user}

    @app.post("/api/auth/login", response_model=AuthOut)
    def login(body: Credentials, request: Request) -> dict[str, Any]:
        client_ip = _client_ip(request)
        key = f"{client_ip}|{body.email.strip().lower()}"
        if not login_ip_limit.hit(client_ip) or not login_limit.hit(key):
            raise too_many(15 * 60)
        user, token = auth_manager().login(body.email, body.password)
        login_limit.reset(key)
        return {"token": token, "user": user}

    @app.post("/api/auth/logout", status_code=204)
    def logout(token: Token) -> Response:
        auth_manager().logout(token)
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
        created = auth_manager().create_reset_token(body.email)
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
        auth_manager().reset_password(body.token, body.new_password)
        return Response(status_code=204)

    # ---------- análises ----------

    @app.post(
        "/api/analyses",
        response_model=AnalysisOut,
        response_model_exclude_unset=True,
        status_code=201,
    )
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
        analysis_store().save(user["id"], analysis)
        return analysis

    @app.get(
        "/api/analyses",
        response_model=list[AnalysisOut],
        response_model_exclude_unset=True,
    )
    def list_analyses(user: User) -> list[dict[str, Any]]:
        return analysis_store().list(user["id"])

    @app.get(
        "/api/analyses/{analysis_id}",
        response_model=AnalysisOut,
        response_model_exclude_unset=True,
    )
    def get_analysis(analysis_id: str, user: User) -> dict[str, Any]:
        analysis = analysis_store().get(user["id"], analysis_id)
        if analysis is None or analysis.get("analysisType") == "repository":
            raise ApiError(404, "Análise não encontrada.")
        return analysis

    @app.post(
        "/api/repositories/analyses",
        response_model=RepositoryAnalysisOut,
        response_model_exclude_unset=True,
        status_code=201,
    )
    async def create_repository_analysis(
        body: RepositoryAnalysisRequest, user: User
    ) -> dict[str, Any]:
        if not repository_analysis_limit.hit(user["id"]):
            raise too_many(60 * 60)

        def analyze_and_store() -> dict[str, Any]:
            analysis = run_repository_analysis(
                body.filename,
                body.archive_base64,
                max_archive_bytes=settings.max_repo_zip_bytes,
            )
            analysis_store().save(user["id"], analysis)
            return analysis

        return await run_in_threadpool(analyze_and_store)

    @app.get(
        "/api/repositories/analyses",
        response_model=list[RepositoryAnalysisListOut],
    )
    def list_repository_analyses(user: User) -> list[dict[str, Any]]:
        return [
            {
                "id": analysis["id"],
                "filename": analysis["filename"],
                "createdAt": analysis["createdAt"],
                "countsBySeverity": analysis["countsBySeverity"],
                "countsByOwasp": analysis["countsByOwasp"],
                "filesAnalyzedCount": len(analysis["filesAnalyzed"]),
                "partial": analysis["partial"],
                "durationSeconds": analysis["durationSeconds"],
                "findingsTruncated": analysis["findingsTruncated"],
                "truncatedFindingsCount": analysis["truncatedFindingsCount"],
                "truncatedOccurrencesCount": analysis["truncatedOccurrencesCount"],
            }
            for analysis in analysis_store().list_by_type(user["id"], "repository")
        ]

    @app.get(
        "/api/repositories/analyses/{analysis_id}",
        response_model=RepositoryAnalysisOut,
        response_model_exclude_unset=True,
    )
    def get_repository_analysis(analysis_id: str, user: User) -> dict[str, Any]:
        analysis = analysis_store().get_by_type(user["id"], analysis_id, "repository")
        if analysis is None:
            raise ApiError(404, "Análise de repositório não encontrada.")
        return analysis

    @app.delete("/api/analyses", status_code=204)
    def clear_analyses(user: User) -> Response:
        analysis_store().clear(user["id"])
        return Response(status_code=204)

    return app


app = create_app()
