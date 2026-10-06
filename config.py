import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    BASE_DIR = BASE_DIR

    # SECRET_KEY signs session cookies and CSRF tokens.
    # In production, set this via an environment variable — never hardcode it.
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32).hex())

    # Reads DATABASE_URL from the environment (e.g. a postgresql:// URL) when
    # set, and falls back to the local SQLite file otherwise — so the app
    # keeps working with zero config for anyone who hasn't set up Postgres.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "instance", "database.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Where encrypted file blobs live on disk (never store plaintext uploads).
    ENCRYPTED_FILES_DIR = os.path.join(BASE_DIR, "encrypted_files")

    # Soft-deleted files stay flagged (not physically removed) in the same
    # blob store until purged for real after TRASH_RETENTION_DAYS.
    TRASH_RETENTION_DAYS = 30

    # Where each user's PRIVATE key is stored, itself encrypted at rest
    # with a key derived from the user's password (see utils/key_manager.py).
    KEYS_DIR = os.path.join(BASE_DIR, "keys")

    MAX_CONTENT_LENGTH = 25 * 1024 * 1024 * 1024  # 25 GB max upload size (streamed, not buffered in RAM)

    ALLOWED_EXTENSIONS = {
        "pdf", "txt", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg",
        "gif", "csv", "zip", "md", "json",
    }

    # File types that can be safely previewed inline (decrypted in memory,
    # never written to disk unencrypted) before a user commits to downloading.
    PREVIEWABLE_TEXT_EXTENSIONS = {"txt", "md", "csv", "json"}
    PREVIEWABLE_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
    PREVIEW_MAX_BYTES = 200 * 1024  # only preview the first 200 KB of text

    # Per-user storage quota (sum of original, unencrypted file sizes).
    DEFAULT_STORAGE_QUOTA = 30 * 1024 * 1024 * 1024  # 30 GB (room for one 25 GB file + a bit more)

    # Session hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes

    # Login rate limiting (in-app lockout, see models.User)
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15

    # Flask-Limiter (per-IP request throttling on sensitive endpoints)
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_HEADERS_ENABLED = True

    # Two-factor authentication
    TOTP_ISSUER = "SecureShare"

    # Public share links (capability-URL model — see utils/share_links.py)
    SHARE_LINK_TOKEN_BYTES = 32
    SHARE_LINK_DEFAULT_EXPIRY_DAYS = 7

    
    # Email verification links / account-recovery notifications.
    # APP_BASE_URL is used to build absolute links inside emails (e.g.
    # http://127.0.0.1:5000 locally, https://yourdomain.com once deployed).
    APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000")
    EMAIL_VERIFY_TOKEN_EXPIRY_HOURS = 24
    # If False (the default while no real SMTP is set up), unverified users
    # can still log in and use the app — a banner just nudges them to verify.
    # Flip to True once real email delivery is configured, to hard-require it.
    REQUIRE_EMAIL_VERIFICATION = os.environ.get("REQUIRE_EMAIL_VERIFICATION", "false").lower() == "true"
