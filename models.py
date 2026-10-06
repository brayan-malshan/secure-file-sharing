import json
from datetime import datetime, timedelta

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # RSA public key (PEM). Safe to store in the clear — it's public.
    public_key = db.Column(db.Text, nullable=False)

    # Path to the user's RSA PRIVATE key on disk. The key file itself is
    # encrypted at rest with a key derived from the user's password
    # (see utils/key_manager.py) — the DB never holds raw private key bytes.
    private_key_path = db.Column(db.String(255), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)

    # --- Two-factor authentication (TOTP, RFC 6238) ---
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    totp_backup_codes = db.Column(db.Text, nullable=True)  # JSON list of salted hashes

        # --- Email verification ---
    email_verified = db.Column(db.Boolean, default=False)
    email_verify_token = db.Column(db.String(64), nullable=True, unique=True)
    email_verify_expires = db.Column(db.DateTime, nullable=True)

    # --- Account recovery (forgot-password without knowing the old one) ---
    # Path to a SECOND copy of the private key, encrypted with the
    # recovery code instead of the password. Only ever unlockable by
    # someone who has the recovery code shown once at registration.
    recovery_key_path = db.Column(db.String(255), nullable=True)

    # --- Personalization / quota ---
    storage_quota = db.Column(db.BigInteger, default=30 * 1024 * 1024 * 1024)
    theme_preference = db.Column(db.String(10), default="dark")  # 'dark' or 'light'
    avatar_color = db.Column(db.String(7), default="#4f8cff")

    files = db.relationship("File", backref="owner", lazy=True, foreign_keys="File.owner_id")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_locked_out(self):
        return bool(self.lockout_until and self.lockout_until > datetime.utcnow())

    def register_failed_login(self, max_attempts, lockout_minutes):
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= max_attempts:
            self.lockout_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)

    def register_successful_login(self):
        self.failed_login_attempts = 0
        self.lockout_until = None

    # --- Backup codes are stored as salted hashes, never in the clear ---
    def set_backup_codes(self, plain_codes):
        self.totp_backup_codes = json.dumps([generate_password_hash(c) for c in plain_codes])

    def consume_backup_code(self, submitted_code):
        if not self.totp_backup_codes:
            return False
        hashes = json.loads(self.totp_backup_codes)
        for h in hashes:
            if check_password_hash(h, submitted_code.strip().replace(" ", "")):
                hashes.remove(h)
                self.totp_backup_codes = json.dumps(hashes)
                return True
        return False

    def remaining_backup_codes(self):
        return len(json.loads(self.totp_backup_codes)) if self.totp_backup_codes else 0

    def storage_used(self):
        return sum(f.file_size for f in self.files if not f.is_trashed) or 0

    def storage_percent(self):
        if not self.storage_quota:
            return 0
        return min(100, round(100 * self.storage_used() / self.storage_quota, 1))

    def initials(self):
        return (self.username[:2] or "??").upper()


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False, unique=True)

    file_size = db.Column(db.BigInteger, nullable=False)

    # SHA-256 of the ORIGINAL plaintext file, computed before encryption.
    # Recomputed after decryption on download to prove integrity.
    sha256_hash = db.Column(db.String(64), nullable=False)

    # AES-GCM nonce (12 bytes, stored as hex) used for this file's encryption.
    nonce = db.Column(db.String(32), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # --- Soft delete / trash ---
    is_trashed = db.Column(db.Boolean, default=False, index=True)
    trashed_at = db.Column(db.DateTime, nullable=True)

    # --- Lightweight stats, denormalized for fast dashboard rendering ---
    download_total = db.Column(db.Integer, default=0)

    permissions = db.relationship("FilePermission", backref="file", lazy=True,
                                   cascade="all, delete-orphan")
    share_links = db.relationship("ShareLink", backref="file", lazy=True,
                                   cascade="all, delete-orphan")

    def extension(self):
        return self.original_filename.rsplit(".", 1)[-1].lower() if "." in self.original_filename else ""

    def human_size(self):
        size = self.file_size or 0
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def days_in_trash(self):
        if not self.trashed_at:
            return 0
        return (datetime.utcnow() - self.trashed_at).days


class FilePermission(db.Model):
    """
    Grants a specific user access to a specific file.
    Each grant carries its OWN copy of the AES file key, encrypted with
    that specific user's RSA public key — so revoking one user's access
    is as simple as deleting their row; nobody else is affected.
    """
    __tablename__ = "file_permissions"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # AES file key, RSA-OAEP encrypted with this user's public key (hex-encoded).
    encrypted_aes_key = db.Column(db.Text, nullable=False)

    permission = db.Column(db.String(20), default="download")  # 'download' or 'view'

    shared_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    max_downloads = db.Column(db.Integer, nullable=True)
    download_count = db.Column(db.Integer, default=0)

    user = db.relationship("User", foreign_keys=[user_id])

    __table_args__ = (db.UniqueConstraint("file_id", "user_id", name="uq_file_user"),)

    def is_expired(self):
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return True
        if self.max_downloads is not None and self.download_count >= self.max_downloads:
            return True
        return False


class ShareLink(db.Model):
    """
    A capability URL that lets anyone holding the link (optionally plus a
    password) download a file WITHOUT having an account. The file's AES key
    is unwrapped once (with the owner's RSA private key) and re-wrapped with
    a key derived from the link's own token via PBKDF2 — so the server never
    persists the AES key in recoverable form; only someone who has the exact
    token (and password, if set) can ever reconstruct it.
    """
    __tablename__ = "share_links"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    label = db.Column(db.String(120), nullable=True)

    # AES key wrapped with a token-derived key: salt(hex) + wrapped(hex)
    wrap_salt = db.Column(db.String(32), nullable=False)
    wrapped_aes_key = db.Column(db.Text, nullable=False)

    password_hash = db.Column(db.String(255), nullable=True)  # optional extra password
    allow_preview = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    max_downloads = db.Column(db.Integer, nullable=True)
    download_count = db.Column(db.Integer, default=0)
    revoked = db.Column(db.Boolean, default=False)

    creator = db.relationship("User", foreign_keys=[created_by])

    def is_expired(self):
        if self.revoked:
            return True
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return True
        if self.max_downloads is not None and self.download_count >= self.max_downloads:
            return True
        return False

    def requires_password(self):
        return bool(self.password_hash)

    def check_password(self, submitted):
        if not self.password_hash:
            return True
        return check_password_hash(self.password_hash, submitted)


class Notification(db.Model):
    """In-app notifications: 'file shared with you', 'access revoked', etc."""
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    category = db.Column(db.String(30), default="info")  # info | success | warning | danger
    message = db.Column(db.String(255), nullable=False)
    link = db.Column(db.String(255), nullable=True)
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id])


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(64), nullable=True)  # denormalized, survives user deletion
    action = db.Column(db.String(64), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=True)
    filename = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    detail = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
