"""Отправка писем через SMTP (stdlib smtplib в отдельном потоке)."""

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)


def _send_sync(settings: Settings, to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or ""
    msg["To"] = to
    msg.set_content(body)

    host = settings.smtp_host or ""
    context = ssl.create_default_context()
    if settings.smtp_port == 465:
        with smtplib.SMTP_SSL(host, settings.smtp_port, timeout=15, context=context) as smtp:
            if settings.smtp_user and settings.smtp_password:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
        return
    with smtplib.SMTP(host, settings.smtp_port, timeout=15) as smtp:
        if settings.smtp_tls:
            smtp.starttls(context=context)
        if settings.smtp_user and settings.smtp_password:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(msg)


async def send_email(to: str, subject: str, body: str) -> bool:
    """Отправляет письмо. Возвращает False, если SMTP не настроен или отправка не удалась."""
    settings = get_settings()
    if not settings.smtp_enabled:
        logger.warning("SMTP не настроен — письмо «%s» не отправлено", subject)
        return False
    try:
        await asyncio.to_thread(_send_sync, settings, to, subject, body)
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("Ошибка отправки письма «%s»: %s", subject, exc.__class__.__name__)
        return False
    return True


async def send_password_reset_email(to: str, token: str) -> None:
    link = f"{get_settings().app_url}/reset-password?token={token}"
    body = (
        "Здравствуйте!\n\n"
        "Мы получили запрос на сброс пароля в ClerkAI. Чтобы задать новый пароль, перейдите по ссылке:\n"
        f"{link}\n\n"
        "Ссылка действует 1 час. Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо.\n"
    )
    await send_email(to, "Сброс пароля ClerkAI", body)
