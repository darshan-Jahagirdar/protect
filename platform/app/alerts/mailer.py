"""Sending email. One small interface, several transports.

- smtp:    Mailpit in the demo; Amazon SES (port 587, STARTTLS) on the server.
- console: logs the message instead of sending (local runs without Mailpit).
- graph:   Microsoft Graph sendMail for Outlook in production. Arrives in milestone 2 (P2);
           Exchange Online is disabling SMTP basic auth by default from the end of Dec 2026.
- memory:  keeps messages in a list, for tests.
"""

import logging
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Protocol

from app.settings import Settings

log = logging.getLogger("protect.mail")


@dataclass(frozen=True)
class Message:
    to: tuple[str, ...]
    subject: str
    body: str


class Mailer(Protocol):
    def send(self, message: Message) -> None: ...


class SmtpMailer:
    def __init__(self, settings: Settings):
        self.s = settings

    def send(self, message: Message) -> None:
        email = EmailMessage()
        email["From"] = self.s.alert_from
        email["To"] = ", ".join(message.to)
        email["Subject"] = message.subject
        email["Date"] = formatdate(localtime=False)
        email["Message-ID"] = make_msgid(domain=self.s.alert_from.rpartition("@")[2] or None)
        email.set_content(message.body)
        with smtplib.SMTP(self.s.smtp_host, self.s.smtp_port, timeout=15) as smtp:
            if self.s.smtp_starttls:
                # smtplib skips certificate checks unless given a context; we send a password.
                smtp.starttls(context=ssl.create_default_context())
            if self.s.smtp_username and self.s.smtp_password:
                smtp.login(self.s.smtp_username, self.s.smtp_password.get_secret_value())
            smtp.send_message(email)


class ConsoleMailer:
    def send(self, message: Message) -> None:
        log.info("EMAIL to=%s subject=%s\n%s", ",".join(message.to), message.subject, message.body)


@dataclass
class MemoryMailer:
    sent: list[Message] = field(default_factory=list)

    def send(self, message: Message) -> None:
        self.sent.append(message)


def mailer_for(settings: Settings) -> Mailer:
    if settings.email_transport == "smtp":
        return SmtpMailer(settings)
    if settings.email_transport == "console":
        return ConsoleMailer()
    raise NotImplementedError("Graph email arrives in milestone 2 (PROGRESS.md P2)")
