"""Contas de usuário, sessões e recuperação de senha."""

from __future__ import annotations

import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .db import Database
from .errors import ApiError
from .security import (
    burn_password_check,
    hash_password,
    hash_token,
    new_token,
    verify_password,
)

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD = 8
MAX_PASSWORD = 128  # limita o custo do scrypt com senhas gigantes


def normalize_email(email: str) -> str:
    return email.strip().lower()


def _validate_email(email: str) -> None:
    if len(email) > 254 or not _EMAIL.match(email):
        raise ApiError(422, "Informe um e-mail válido.")


def _validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise ApiError(422, "Use uma senha com pelo menos 8 caracteres.")
    if len(password) > MAX_PASSWORD:
        raise ApiError(422, "A senha pode ter no máximo 128 caracteres.")


class AuthManager:
    def __init__(
        self,
        db: Database,
        *,
        session_ttl_seconds: int,
        reset_ttl_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._db = db
        self._session_ttl = session_ttl_seconds
        self._reset_ttl = reset_ttl_seconds
        self._clock = clock

    # ---------- cadastro / login ----------

    def register(self, email: str, password: str) -> tuple[dict[str, Any], str]:
        email = normalize_email(email)
        _validate_email(email)
        _validate_password(password)
        user_id = str(uuid.uuid4())
        created = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        password_hash = hash_password(password)
        try:
            with self._db.connect() as conn:
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, email, password_hash, created),
                )
        except Exception as exc:
            # SQLite e MySQL usam tipos diferentes para violação de UNIQUE.
            is_integrity = isinstance(exc, sqlite3.IntegrityError)
            if not is_integrity:
                try:
                    import mysql.connector
                    is_integrity = isinstance(exc, mysql.connector.IntegrityError)
                except ImportError:
                    pass
            if is_integrity:
                raise ApiError(409, "Este e-mail já está cadastrado.") from exc
            raise
        user = {"id": user_id, "email": email}
        return user, self._create_session(user_id)

    def login(self, email: str, password: str) -> tuple[dict[str, Any], str]:
        email = normalize_email(email)
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT id, email, password_hash FROM users WHERE email = ?", (email,)
            ).fetchone()
        if row is None:
            burn_password_check(password)
            raise ApiError(401, "E-mail ou senha incorretos.")
        if not verify_password(password, row[2]):
            raise ApiError(401, "E-mail ou senha incorretos.")
        return {"id": row[0], "email": row[1]}, self._create_session(row[0])

    # ---------- sessões ----------

    def _create_session(self, user_id: str) -> str:
        token = new_token()
        now = int(self._clock())
        with self._db.connect() as conn:
            conn.execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (now,)
            )  # limpeza oportunista
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (hash_token(token), user_id, now, now + self._session_ttl),
            )
        return token

    def user_for_token(self, token: str) -> dict[str, Any] | None:
        now = int(self._clock())
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash = ? AND s.expires_at > ?",
                (hash_token(token), now),
            ).fetchone()
        return {"id": row[0], "email": row[1]} if row else None

    def logout(self, token: str) -> None:
        with self._db.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))

    # ---------- recuperação de senha ----------

    def create_reset_token(self, email: str) -> tuple[str, str] | None:
        """Retorna (email, token) se a conta existir; None caso contrário.

        O chamador deve responder igual nos dois casos (sem revelar se o e-mail existe).
        """
        email = normalize_email(email)
        with self._db.connect() as conn:
            row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if row is None:
                return None
            now = int(self._clock())
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ? OR expires_at <= ?", (row[0], now))
            token = new_token()
            conn.execute(
                "INSERT INTO reset_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (hash_token(token), row[0], now + self._reset_ttl),
            )
        return email, token

    def reset_password(self, token: str, new_password: str) -> None:
        _validate_password(new_password)
        now = int(self._clock())
        digest = hash_token(token)
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT user_id FROM reset_tokens WHERE token_hash = ? AND expires_at > ?",
                (digest, now),
            ).fetchone()
            if row is None:
                raise ApiError(400, "Link de recuperação inválido ou expirado.")
            user_id = row[0]
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user_id,))  # uso único
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(new_password), user_id),
            )
            # Quem tinha a senha antiga (ou uma sessão roubada) perde o acesso.
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
