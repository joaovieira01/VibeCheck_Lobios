"""Envio do e-mail de recuperação de senha."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Protocol

from .config import Settings

logger = logging.getLogger("vibecheck.mailer")


class Mailer(Protocol):
    def send_password_reset(self, to_email: str, reset_url: str) -> None: ...


class LogMailer:
    """Desenvolvimento: não envia nada, só registra o link no log do servidor."""

    def send_password_reset(self, to_email: str, reset_url: str) -> None:
        logger.warning(
            "SMTP não configurado; link de recuperação para %s: %s", to_email, reset_url
        )


class SmtpMailer:
    def __init__(self, settings: Settings) -> None:
        self._s = settings

    def send_password_reset(self, to_email: str, reset_url: str) -> None:
        message = EmailMessage()
        message["Subject"] = "VibeCheck — recuperação de senha"
        message["From"] = self._s.smtp_from
        message["To"] = to_email
        message.set_content(
            "Recebemos um pedido para redefinir a senha da sua conta VibeCheck.\n\n"
            f"Abra o link abaixo (válido por {self._s.reset_ttl_minutes} minutos):\n"
            f"{reset_url}\n\n"
            "Se você não fez esse pedido, ignore este e-mail."
        )
        with smtplib.SMTP(self._s.smtp_host, self._s.smtp_port, timeout=10) as smtp:
            if self._s.smtp_starttls:
                # Contexto padrão = valida certificado e hostname (starttls() sem
                # contexto NÃO valida).
                smtp.starttls(context=ssl.create_default_context())
            if self._s.smtp_user:
                smtp.login(self._s.smtp_user, self._s.smtp_password)
            smtp.send_message(message)


def build_mailer(settings: Settings) -> Mailer:
    return SmtpMailer(settings) if settings.smtp_host else LogMailer()
