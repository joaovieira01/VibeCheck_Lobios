class ApiError(Exception):
    """Erro previsto, com status HTTP e mensagem em português para o usuário."""

    def __init__(self, status_code: int, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.headers = headers or {}
