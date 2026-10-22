import os
import tempfile
import unittest

from app.auth import AuthManager
from app.db import Database
from app.errors import ApiError
from app.service import detect_language, run_analysis
from app.storage import AnalysisStore


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(os.path.join(self.tmp.name, "t.db"))
        self.now = [1_000_000.0]
        self.auth = AuthManager(
            self.db, session_ttl_seconds=100, reset_ttl_seconds=50, clock=lambda: self.now[0]
        )


class AuthTests(Base):
    def test_register_login_session_logout(self):
        user, token = self.auth.register("  Ana@Example.COM ", "senha-forte-1")
        self.assertEqual(user["email"], "ana@example.com")
        self.assertEqual(self.auth.user_for_token(token)["id"], user["id"])
        logged, token2 = self.auth.login("ANA@example.com", "senha-forte-1")
        self.assertEqual(logged["id"], user["id"])
        self.auth.logout(token2)
        self.assertIsNone(self.auth.user_for_token(token2))
        self.assertIsNotNone(self.auth.user_for_token(token))  # outra sessão segue válida

    def test_duplicate_email_conflict(self):
        self.auth.register("a@b.co", "senha-forte-1")
        with self.assertRaises(ApiError) as ctx:
            self.auth.register("A@B.CO", "outra-senha-2")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_validation(self):
        for email, pwd in [("sem-arroba", "senha-forte-1"), ("a@b", "senha-forte-1"),
                           ("a@b.co", "curta"), ("a@b.co", "x" * 129)]:
            with self.subTest(email=email, pwd=len(pwd)):
                with self.assertRaises(ApiError) as ctx:
                    self.auth.register(email, pwd)
                self.assertEqual(ctx.exception.status_code, 422)

    def test_login_failures_use_same_message(self):
        self.auth.register("a@b.co", "senha-forte-1")
        messages = set()
        for email, pwd in [("a@b.co", "errada-errada"), ("nao@existe.co", "senha-forte-1")]:
            with self.assertRaises(ApiError) as ctx:
                self.auth.login(email, pwd)
            self.assertEqual(ctx.exception.status_code, 401)
            messages.add(ctx.exception.message)
        self.assertEqual(len(messages), 1)

    def test_session_expires(self):
        _, token = self.auth.register("a@b.co", "senha-forte-1")
        self.now[0] += 99
        self.assertIsNotNone(self.auth.user_for_token(token))
        self.now[0] += 2
        self.assertIsNone(self.auth.user_for_token(token))

    def test_tokens_are_not_stored_in_clear(self):
        _, token = self.auth.register("a@b.co", "senha-forte-1")
        with self.db.connect() as conn:
            stored = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
        self.assertNotIn(token, stored)

    def test_password_reset_flow(self):
        self.auth.register("a@b.co", "senha-antiga-1")
        _, old_token = self.auth.login("a@b.co", "senha-antiga-1")
        created = self.auth.create_reset_token("A@b.co")
        self.assertIsNotNone(created)
        email, reset = created
        self.assertEqual(email, "a@b.co")

        self.auth.reset_password(reset, "senha-nova-22")
        self.assertIsNone(self.auth.user_for_token(old_token))  # sessões revogadas
        with self.assertRaises(ApiError):
            self.auth.login("a@b.co", "senha-antiga-1")
        self.auth.login("a@b.co", "senha-nova-22")
        with self.assertRaises(ApiError) as ctx:  # uso único
            self.auth.reset_password(reset, "outra-senha-33")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_reset_unknown_email_and_expiry(self):
        self.assertIsNone(self.auth.create_reset_token("ninguem@x.co"))
        self.auth.register("a@b.co", "senha-antiga-1")
        _, reset = self.auth.create_reset_token("a@b.co")
        self.now[0] += 51
        with self.assertRaises(ApiError):
            self.auth.reset_password(reset, "senha-nova-22")

    def test_new_reset_invalidates_previous(self):
        self.auth.register("a@b.co", "senha-antiga-1")
        _, first = self.auth.create_reset_token("a@b.co")
        _, second = self.auth.create_reset_token("a@b.co")
        with self.assertRaises(ApiError):
            self.auth.reset_password(first, "senha-nova-22")
        self.auth.reset_password(second, "senha-nova-22")


class StoreTests(Base):
    def _analysis(self, n):
        return {"id": f"id-{n}", "createdAt": f"2026-01-01T00:00:{n:02d}.000Z", "findings": [], "n": n}

    def test_history_is_isolated_ordered_and_capped(self):
        a, _ = self.auth.register("a@b.co", "senha-forte-1")
        b, _ = self.auth.register("b@b.co", "senha-forte-1")
        store = AnalysisStore(self.db, max_history=3)
        for n in range(5):
            store.save(a["id"], self._analysis(n))
        store.save(b["id"], self._analysis(40))
        self.assertEqual([x["n"] for x in store.list(a["id"])], [4, 3, 2])
        self.assertEqual([x["n"] for x in store.list(b["id"])], [40])
        self.assertIsNone(store.get(b["id"], "id-4"))  # sem acesso entre contas
        self.assertEqual(store.get(a["id"], "id-4")["n"], 4)

    def test_clear_only_affects_owner(self):
        a, _ = self.auth.register("a@b.co", "senha-forte-1")
        b, _ = self.auth.register("b@b.co", "senha-forte-1")
        store = AnalysisStore(self.db)
        store.save(a["id"], self._analysis(1))
        store.save(b["id"], self._analysis(2))
        store.clear(a["id"])
        self.assertEqual(store.list(a["id"]), [])
        self.assertEqual(len(store.list(b["id"])), 1)

    def test_memory_db_rejected(self):
        with self.assertRaises(ValueError):
            Database(":memory:")


class ServiceTests(unittest.TestCase):
    KW = dict(max_source_bytes=1_000_000, max_line_chars=1000)

    def test_result_shape_matches_frontend_type(self):
        result = run_analysis("app.py", "DEBUG = True\r\nx = 1", **self.KW)
        self.assertEqual(
            set(result),
            {"id", "filename", "language", "linesAnalyzed", "createdAt", "durationMs", "findings", "rulesRun"},
        )
        self.assertEqual(result["language"], "Python")
        self.assertEqual(result["linesAnalyzed"], 2)
        self.assertTrue(result["createdAt"].endswith("Z"))
        self.assertEqual(result["findings"][0]["owaspId"], "A02")

    def test_limits(self):
        with self.assertRaises(ApiError) as ctx:
            run_analysis("a.py", "x" * 101, max_source_bytes=100, max_line_chars=1000)
        self.assertEqual(ctx.exception.status_code, 413)
        # o limite é em bytes UTF-8, como no frontend (Blob.size)
        with self.assertRaises(ApiError):
            run_analysis("a.py", "ç" * 60, max_source_bytes=100, max_line_chars=1000)
        with self.assertRaises(ApiError) as ctx:
            run_analysis("a.py", "  \n ", **self.KW)
        self.assertEqual(ctx.exception.status_code, 422)

    def test_lone_surrogate_is_rejected_cleanly(self):
        with self.assertRaises(ApiError):
            run_analysis("a.py", "x = '\ud800'", **self.KW)

    def test_detect_language(self):
        self.assertEqual(detect_language("a.TSX"), "TypeScript / React")
        self.assertEqual(detect_language("x.yml"), "YML")
        self.assertEqual(detect_language(""), "Texto")


if __name__ == "__main__":
    unittest.main()
