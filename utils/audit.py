from flask import request
from models import db, AuditLog


def log_action(user, action, file=None, detail=None):
    """
    Writes one row to the audit_logs table. Call this for every
    security-relevant event: register, login, login_failed, logout,
    upload, share, revoke, download, unauthorized_attempt, etc.
    `user` may be None for anonymous/unauthenticated events.
    """
    entry = AuditLog(
        user_id=getattr(user, "id", None),
        username=getattr(user, "username", None) or (detail if action == "login_failed" else None),
        action=action,
        file_id=getattr(file, "id", None) if file else None,
        filename=getattr(file, "original_filename", None) if file else None,
        ip_address=request.remote_addr if request else None,
        detail=detail,
    )
    db.session.add(entry)
    db.session.commit()
