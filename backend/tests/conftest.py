"""Configuração isolada e previsível para a suíte de testes."""

import os
import shutil
import tempfile

# Mantém os testes independentes do .env e de serviços externos.
_TEST_DIRECTORY = tempfile.mkdtemp(prefix="vibecheck-tests-")
os.environ["VIBECHECK_DB_ENGINE"] = "sqlite"
os.environ["VIBECHECK_DB_PATH"] = os.path.join(_TEST_DIRECTORY, "testes.db")
os.environ["AI_ENABLED"] = "false"


def pytest_sessionfinish(session, exitstatus):
    """Remove o banco temporário ao terminar a sessão pytest."""
    shutil.rmtree(_TEST_DIRECTORY)
