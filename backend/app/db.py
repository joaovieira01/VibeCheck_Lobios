"""Banco de dados SQLite, MySQL ou PostgreSQL configurado por variáveis VIBECHECK_DB_*."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Any

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
CREATE TABLE IF NOT EXISTS reset_tokens (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reset_user ON reset_tokens (user_id);
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_user_created ON analyses (user_id, created_at DESC);
"""

MYSQL_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY, email VARCHAR(254) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL, created_at VARCHAR(40) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS sessions (
        token_hash CHAR(64) PRIMARY KEY, user_id VARCHAR(36) NOT NULL,
        created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
        INDEX idx_sessions_user (user_id),
        CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS reset_tokens (
        token_hash CHAR(64) PRIMARY KEY, user_id VARCHAR(36) NOT NULL,
        expires_at BIGINT NOT NULL, INDEX idx_reset_user (user_id),
        CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS analyses (
        id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL,
        created_at VARCHAR(40) NOT NULL, payload LONGTEXT NOT NULL,
        INDEX idx_analyses_user_created (user_id, created_at),
        CONSTRAINT fk_analyses_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]

POSTGRES_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY, email VARCHAR(254) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL, created_at VARCHAR(40) NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        token_hash CHAR(64) PRIMARY KEY, user_id VARCHAR(36) NOT NULL,
        created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
        CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id)",
    """CREATE TABLE IF NOT EXISTS reset_tokens (
        token_hash CHAR(64) PRIMARY KEY, user_id VARCHAR(36) NOT NULL,
        expires_at BIGINT NOT NULL,
        CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_reset_user ON reset_tokens (user_id)",
    """CREATE TABLE IF NOT EXISTS analyses (
        id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL,
        created_at VARCHAR(40) NOT NULL, payload TEXT NOT NULL,
        CONSTRAINT fk_analyses_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_analyses_user_created ON analyses (user_id, created_at DESC)",
]


class _MySQLConnection:
    """Adaptador pequeno para manter a interface conn.execute usada pelo projeto."""
    def __init__(self, raw: Any):
        self.raw = raw
    def execute(self, sql: str, params: tuple = ()):
        cursor = self.raw.cursor()
        cursor.execute(sql.replace("?", "%s"), params)
        return cursor
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            self.raw.rollback()
        else:
            self.raw.commit()
        self.raw.close()
        return False


class _PostgreSQLConnection:
    """Adapta placeholders do projeto ao formato usado pelo psycopg."""
    def __init__(self, raw: Any):
        self.raw = raw
    def execute(self, sql: str, params: tuple = ()):
        return self.raw.execute(sql.replace("?", "%s"), params)


class Database:
    def __init__(self, path: Any) -> None:
        # Compatível com Database(path) nos testes existentes e Database(settings) na API.
        if hasattr(path, "db_engine"):
            settings = path
            self.engine = settings.db_engine
            self._path = str(settings.db_path)
            self._mysql = {
                "host": settings.db_host, "port": settings.db_port,
                "database": settings.db_name, "user": settings.db_user,
                "password": settings.db_password,
                "charset": "utf8mb4", "autocommit": False,
            }
            self._db_url = settings.db_url
        else:
            self.engine = "sqlite"
            self._path = str(path)
            self._mysql = {}
            self._db_url = ""
        if self.engine not in {"sqlite", "mysql", "postgres"}:
            raise RuntimeError(
                "VIBECHECK_DB_ENGINE deve ser 'sqlite', 'mysql' ou 'postgres'."
            )
        if self.engine == "sqlite":
            if self._path == ":memory:":
                raise ValueError("Use um arquivo em disco; ':memory:' não é suportado.")
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            with self.connect() as conn:
                conn.executescript(SQLITE_SCHEMA)
        elif self.engine == "mysql":
            if not self._mysql["password"]:
                raise RuntimeError("Defina VIBECHECK_DB_PASSWORD no arquivo .env.")
            try:
                import mysql.connector
            except ImportError as exc:
                raise RuntimeError("Instale mysql-connector-python: pip install -r requirements.txt") from exc
            # O banco precisa existir previamente; o usuário da aplicação deve ter acesso a ele.
            with self.connect() as conn:
                for statement in MYSQL_SCHEMA:
                    conn.execute(statement)
        else:
            if not self._db_url:
                raise RuntimeError("Defina VIBECHECK_DB_URL com a URL do PostgreSQL.")
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError(
                    "Instale psycopg[binary]: pip install -r requirements.txt"
                ) from exc
            with self.connect() as conn:
                for statement in POSTGRES_SCHEMA:
                    conn.execute(statement)

    @contextmanager
    def connect(self) -> Iterator[Any]:
        if self.engine == "mysql":
            import mysql.connector
            raw = mysql.connector.connect(**self._mysql)
            adapter = _MySQLConnection(raw)
            try:
                yield adapter
                raw.commit()
            except Exception:
                raw.rollback()
                raise
            finally:
                raw.close()
        elif self.engine == "postgres":
            import psycopg
            raw = psycopg.connect(self._db_url)
            adapter = _PostgreSQLConnection(raw)
            try:
                yield adapter
                raw.commit()
            except Exception:
                raw.rollback()
                raise
            finally:
                raw.close()
        else:
            conn = sqlite3.connect(self._path, timeout=10)
            try:
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA journal_mode=WAL")
                with conn:
                    yield conn
            finally:
                conn.close()
