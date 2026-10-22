"""Histórico de análises por usuário."""

from __future__ import annotations

import json
from typing import Any

from .db import Database


class AnalysisStore:
    def __init__(self, db: Database, max_history: int = 20) -> None:
        self._db = db
        self._max_history = max_history

    def save(self, user_id: str, analysis: dict[str, Any]) -> None:
        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO analyses (id, user_id, created_at, payload) VALUES (?, ?, ?, ?)",
                (
                    analysis["id"],
                    user_id,
                    analysis["createdAt"],
                    json.dumps(analysis, ensure_ascii=False),
                ),
            )
            # Mantém só as N mais recentes do usuário (igual ao limite do frontend).
            conn.execute(
                "DELETE FROM analyses WHERE user_id = ? AND id NOT IN ("
                "  SELECT id FROM (SELECT id FROM analyses WHERE user_id = ? "
                "  ORDER BY created_at DESC, id DESC LIMIT ?) AS keep_ids)",
                (user_id, user_id, self._max_history),
            )

    def list(self, user_id: str) -> list[dict[str, Any]]:
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM analyses WHERE user_id = ? "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (user_id, self._max_history),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get(self, user_id: str, analysis_id: str) -> dict[str, Any] | None:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM analyses WHERE user_id = ? AND id = ?",
                (user_id, analysis_id),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def clear(self, user_id: str) -> int:
        with self._db.connect() as conn:
            return conn.execute("DELETE FROM analyses WHERE user_id = ?", (user_id,)).rowcount
