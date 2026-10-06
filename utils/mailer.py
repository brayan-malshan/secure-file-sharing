"""
mailer.py — Sends outgoing email (verification links, password-reset
notifications) via SMTP when configured, or falls back to writing the
message to a local log file + printing it to the console when it isn't.

This means the whole email-verification / password-reset flow is fully
testable on a local machine with no real mail server set up — you just
read the "email" out of logs/dev_emails.log or the terminal instead of
an inbox. Once real SMTP credentials are set (via environment variables),
it starts actually sending mail with zero code changes.
"""
import os
import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage

DEV_EMAIL_LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "dev_emails.log")


def _smtp_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST"))


def _send_via_smtp(to_addr: str, subject: str, body: str) -> None:
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    from_addr = os.environ.get("SMTP_FROM", username or "no-reply@secureshare.local")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls(context=context)
        if username and password:
            server.login(username, password)
        server.send_message(msg)


def _send_via_dev_fallback(to_addr: str, subject: str, body: str) -> None:
    os.makedirs(os.path.dirname(DEV_EMAIL_LOG_PATH), exist_ok=True)
    entry = (
        f"\n{'=' * 70}\n"
        f"[{datetime.utcnow().isoformat()}Z] DEV EMAIL (no SMTP configured — not actually sent)\n"
        f"To:      {to_addr}\n"
        f"Subject: {subject}\n"
        f"{'-' * 70}\n"
        f"{body}\n"
        f"{'=' * 70}\n"
    )
    print(entry)  # visible right in the terminal running `python app.py`
    with open(DEV_EMAIL_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(entry)


def send_email(to_addr: str, subject: str, body: str) -> None:
    """Best-effort send — never raises. A failed/unsent email should not
    block the request that triggered it (registration, password reset)."""
    try:
        if _smtp_configured():
            _send_via_smtp(to_addr, subject, body)
        else:
            _send_via_dev_fallback(to_addr, subject, body)
    except Exception as e:
        # Fall back to logging locally so the flow is still testable even
        # if real SMTP is misconfigured (wrong host/creds/etc).
        print(f"[mailer] Failed to send email to {to_addr}: {e}")
        _send_via_dev_fallback(to_addr, subject, body + f"\n\n(NOTE: real SMTP send failed: {e})")