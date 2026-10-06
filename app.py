from dotenv import load_dotenv
load_dotenv()

import csv
import io
import os
import secrets
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, redirect, url_for, flash, request, send_file,
    abort, session, jsonify, make_response, Response,
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user,
)
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

from config import Config
from models import db, User, File, FilePermission, AuditLog, ShareLink, Notification
from utils import crypto
from utils.key_manager import (
    create_user_keypair, load_user_private_key, load_private_key_via_recovery,
    create_recovery_envelope,
)
from utils.audit import log_action
from utils.permissions import user_can_access, revoke_access
from utils.notifications import notify, unread_count
from utils.two_factor import (
    generate_totp_secret, provisioning_uri, verify_totp_code, generate_backup_codes,
)
from utils.share_links import generate_token, wrap_key_for_link, unwrap_key_for_link
from utils.mailer import send_email
from utils.recovery import generate_recovery_code, normalize_recovery_code

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[])

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.context_processor
def inject_globals():
    recent_notifs = []
    if current_user.is_authenticated:
        recent_notifs = (
            Notification.query.filter_by(user_id=current_user.id)
            .order_by(Notification.created_at.desc()).limit(6).all()
        )
    return {
        "notif_unread_count": unread_count(current_user) if current_user.is_authenticated else 0,
        "recent_notifs": recent_notifs,
        "current_theme": (current_user.theme_preference if current_user.is_authenticated else request.cookies.get("theme", "dark")),
        "now": datetime.utcnow(),
    }


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]


def paginate(query, page, per_page=10):
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    pages = max(1, (total + per_page - 1) // per_page)
    return items, total, pages


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []
        if not (3 <= len(username) <= 64) or not username.isalnum():
            errors.append("Username must be 3-64 alphanumeric characters.")
        if "@" not in email or "." not in email:
            errors.append("Please provide a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if User.query.filter_by(username=username).first():
            errors.append("That username is already taken.")
        if User.query.filter_by(email=email).first():
            errors.append("That email is already registered.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", username=username, email=email)

             # Generate the user's RSA keypair. The private key is encrypted at
        # rest with a key derived from their password (see key_manager.py).
        # A recovery code is also generated now — it unlocks a SEPARATE
        # copy of the same private key, and is the only way to reset a
        # forgotten password without already knowing it.
        recovery_code = generate_recovery_code()
        public_pem, private_key_path, recovery_key_path = create_user_keypair(
            username, password, app.config["KEYS_DIR"], recovery_code=recovery_code
        )

        verify_token = secrets.token_urlsafe(32)

        user = User(
            username=username,
            email=email,
            public_key=public_pem,
            private_key_path=private_key_path,
            recovery_key_path=recovery_key_path,
            storage_quota=app.config["DEFAULT_STORAGE_QUOTA"],
            email_verify_token=verify_token,
            email_verify_expires=datetime.utcnow() + timedelta(hours=app.config["EMAIL_VERIFY_TOKEN_EXPIRY_HOURS"]),
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        verify_link = f"{app.config['APP_BASE_URL']}{url_for('verify_email', token=verify_token)}"
        send_email(
            email,
            "Verify your SecureShare email",
            f"Hi {username},\n\n"
            f"Click the link below to verify your email address:\n{verify_link}\n\n"
            f"This link expires in {app.config['EMAIL_VERIFY_TOKEN_EXPIRY_HOURS']} hours.\n\n"
            f"If you didn't create this account, you can ignore this email.",
        )

        log_action(user, "register")
        # Recovery code is shown exactly once, right now — stash it in the
        # session just long enough to render the next page, never in the DB.
        session["_recovery_code_to_show"] = recovery_code
        session["_recovery_code_username"] = username
        flash("Account created. Save your recovery code below, then check your email to verify your address.", "success")
        return redirect(url_for("show_recovery_code"))

    return render_template("register.html")

@app.route("/register/recovery-code")
@limiter.limit("20 per hour")
def show_recovery_code():
    """Shown exactly once, right after registration (or after a password
    reset / regeneration rotates the code). Pulled from the session so it
    is never persisted anywhere — reloading this page after leaving it
    shows nothing, by design."""
    code = session.pop("_recovery_code_to_show", None)
    username = session.pop("_recovery_code_username", None)
    if not code:
        flash("That recovery code has already been shown and can't be displayed again. "
              "If you're logged in, you can generate a new one from Settings.", "warning")
        return redirect(url_for("login"))
    return render_template("recovery_code.html", code=code, username=username)


@app.route("/verify-email/<token>")
def verify_email(token):
    user = User.query.filter_by(email_verify_token=token).first()
    if not user or not user.email_verify_expires or user.email_verify_expires < datetime.utcnow():
        flash("That verification link is invalid or has expired.", "danger")
        return redirect(url_for("login"))

    user.email_verified = True
    user.email_verify_token = None
    user.email_verify_expires = None
    db.session.commit()
    log_action(user, "email_verified")
    flash("Email verified — thanks!", "success")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def resend_verification():
    if current_user.email_verified:
        flash("Your email is already verified.", "info")
        return redirect(request.referrer or url_for("dashboard"))

    current_user.email_verify_token = secrets.token_urlsafe(32)
    current_user.email_verify_expires = datetime.utcnow() + timedelta(
        hours=app.config["EMAIL_VERIFY_TOKEN_EXPIRY_HOURS"]
    )
    db.session.commit()

    verify_link = f"{app.config['APP_BASE_URL']}{url_for('verify_email', token=current_user.email_verify_token)}"
    send_email(
        current_user.email,
        "Verify your SecureShare email",
        f"Hi {current_user.username},\n\nClick the link below to verify your email address:\n{verify_link}\n\n"
        f"This link expires in {app.config['EMAIL_VERIFY_TOKEN_EXPIRY_HOURS']} hours.",
    )
    flash("Verification email sent.", "success")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        recovery_code = normalize_recovery_code(request.form.get("recovery_code", ""))
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        # Deliberately generic error message throughout this route — it
        # must never reveal whether an email exists, whether the code was
        # wrong vs the email was wrong, etc. That information helps an
        # attacker enumerate accounts or brute-force recovery codes.
        generic_error = "That email and recovery code combination is not valid."

        if len(new_password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("forgot_password.html", email=email)
        if new_password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("forgot_password.html", email=email)

        user = User.query.filter_by(email=email).first()

        if not user or not user.recovery_key_path or not os.path.exists(user.recovery_key_path):
            log_action(None, "password_reset_failed", detail=f"email={email}")
            flash(generic_error, "danger")
            return render_template("forgot_password.html", email=email)

        try:
            private_pem = load_private_key_via_recovery(user.recovery_key_path, recovery_code)
        except Exception:
            log_action(user, "password_reset_failed", detail="bad recovery code")
            flash(generic_error, "danger")
            return render_template("forgot_password.html", email=email)

        # Success: re-wrap the SAME private key under the new password,
        # then rotate the recovery code (the old one is now "spent" —
        # showing it as a one-time code and then letting it be reused
        # indefinitely would defeat the point).
        new_encrypted_blob = crypto.encrypt_private_key_for_storage(private_pem, new_password)
        with open(user.private_key_path, "wb") as f:
            f.write(new_encrypted_blob)

        new_recovery_code = generate_recovery_code()
        user.recovery_key_path = create_recovery_envelope(
            user.username, new_recovery_code, private_pem, app.config["KEYS_DIR"]
        )
        user.set_password(new_password)
        db.session.commit()

        log_action(user, "password_reset_via_recovery_code")
        send_email(
            user.email,
            "Your SecureShare password was reset",
            f"Hi {user.username},\n\nYour password was just reset using your account recovery code. "
            f"If this wasn't you, your recovery code has already been rotated and is now useless to "
            f"whoever reset it — but please check your account's recent activity in Audit Logs.",
        )

        session["_recovery_code_to_show"] = new_recovery_code
        session["_recovery_code_username"] = user.username
        flash("Password reset. Here is your new recovery code — the old one no longer works.", "success")
        return redirect(url_for("show_recovery_code"))

    return render_template("forgot_password.html", email="")


@app.route("/settings/recovery-code/regenerate", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def regenerate_recovery_code():
    """Requires the CURRENT password, because generating a new recovery
    envelope means re-wrapping the private key — which needs the private
    key unlocked first."""
    password = request.form.get("password", "")
    try:
        private_key = load_user_private_key(current_user.private_key_path, password)
    except Exception:
        flash("Incorrect password.", "danger")
        return redirect(url_for("settings"))

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    new_code = generate_recovery_code()
    current_user.recovery_key_path = create_recovery_envelope(
        current_user.username, new_code, private_pem, app.config["KEYS_DIR"]
    )
    db.session.commit()
    log_action(current_user, "recovery_code_regenerated")

    session["_recovery_code_to_show"] = new_code
    session["_recovery_code_username"] = current_user.username
    flash("New recovery code generated. Your old recovery code no longer works.", "success")
    return redirect(url_for("show_recovery_code"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("15 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user and user.is_locked_out():
            flash("Account temporarily locked due to failed login attempts. Try again later.", "danger")
            log_action(user, "login_blocked_lockout")
            return render_template("login.html")

        if user and user.check_password(password):
            if app.config["REQUIRE_EMAIL_VERIFICATION"] and not user.email_verified:
                flash("Please verify your email address before logging in. Check your inbox for the link we sent when you registered.", "danger")
                log_action(user, "login_blocked_unverified_email")
                return render_template("login.html")

            if user.totp_enabled:
                # Password verified, but a second factor is required before
                # a real session is created. Stash a short-lived pending
                # login rather than logging the user in outright.
                session["pending_2fa_user_id"] = user.id
                session["pending_2fa_expires"] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
                log_action(user, "login_password_ok_awaiting_2fa")
                return redirect(url_for("login_verify_2fa"))

            user.register_successful_login()
            db.session.commit()
            login_user(user)
            log_action(user, "login")
            flash(f"Welcome back, {user.username}.", "success")
            return redirect(url_for("dashboard"))

        # Invalid credentials: record failed attempt (rate limiting)
        if user:
            user.register_failed_login(app.config["MAX_LOGIN_ATTEMPTS"], app.config["LOGIN_LOCKOUT_MINUTES"])
            db.session.commit()
        log_action(None, "login_failed", detail=username)
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/login/verify-2fa", methods=["GET", "POST"])
@limiter.limit("15 per minute")
def login_verify_2fa():
    pending_id = session.get("pending_2fa_user_id")
    expires = session.get("pending_2fa_expires")
    if not pending_id or not expires or datetime.fromisoformat(expires) < datetime.utcnow():
        session.pop("pending_2fa_user_id", None)
        session.pop("pending_2fa_expires", None)
        flash("Your login attempt expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    user = db.session.get(User, pending_id)
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "")
        use_backup = request.form.get("use_backup") == "1"

        ok = user.consume_backup_code(code) if use_backup else verify_totp_code(user.totp_secret, code)

        if ok:
            if use_backup:
                db.session.commit()
            session.pop("pending_2fa_user_id", None)
            session.pop("pending_2fa_expires", None)
            user.register_successful_login()
            db.session.commit()
            login_user(user)
            log_action(user, "login_2fa")
            flash(f"Welcome back, {user.username}.", "success")
            return redirect(url_for("dashboard"))

        log_action(user, "login_2fa_failed")
        flash("That code didn't work. Try again.", "danger")

    return render_template("verify_2fa.html", username=user.username)


@app.route("/logout")
@login_required
def logout():
    log_action(current_user, "logout")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Authenticated routes — dashboard & files
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    my_files = File.query.filter_by(owner_id=current_user.id, is_trashed=False).order_by(File.created_at.desc()).all()
    shared_with_me = (
        FilePermission.query.filter_by(user_id=current_user.id)
        .join(File, FilePermission.file_id == File.id)
        .filter(File.is_trashed.is_(False))
        .all()
    )
    total_downloads = AuditLog.query.filter_by(user_id=current_user.id, action="download").count()
    recent_activity = (
        AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(8).all()
    )
    active_links = ShareLink.query.filter_by(created_by=current_user.id, revoked=False).count()

    # Simple breakdown of storage by file extension, for a small chart.
    breakdown = {}
    for f in my_files:
        ext = f.extension() or "other"
        breakdown[ext] = breakdown.get(ext, 0) + f.file_size
    breakdown = dict(sorted(breakdown.items(), key=lambda kv: -kv[1])[:6])

    return render_template(
        "dashboard.html",
        my_files=my_files,
        shared_with_me=shared_with_me,
        total_downloads=total_downloads,
        recent_activity=recent_activity,
        active_links=active_links,
        breakdown=breakdown,
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or uploaded.filename == "":
            flash("Please choose a file to upload.", "danger")
            return redirect(url_for("upload"))

        filename = secure_filename(uploaded.filename)
        if not allowed_file(filename):
            flash("That file type is not allowed.", "danger")
            return redirect(url_for("upload"))

                # Quota is checked against the CLIENT-reported size first (cheap,
        # avoids writing a partial file for an obviously-too-big upload),
        # then re-checked against the real bytes read as a hard backstop —
        # a client can lie about content-length, but it can't lie about
        # how many bytes actually arrive on the wire.
        declared_size = request.content_length or 0
        if declared_size and current_user.storage_used() + declared_size > current_user.storage_quota:
            flash("This upload would exceed your storage quota. Delete some files or empty your trash.", "danger")
            return redirect(url_for("upload"))

        aes_key = crypto.generate_aes_key()
        encrypted_filename = f"{current_user.id}_{datetime.utcnow().timestamp()}_{filename}.enc"
        os.makedirs(app.config["ENCRYPTED_FILES_DIR"], exist_ok=True)
        enc_path = os.path.join(app.config["ENCRYPTED_FILES_DIR"], encrypted_filename)

        quota_remaining = current_user.storage_quota - current_user.storage_used()
        bytes_read = 0

        def _read_chunk(n):
            nonlocal bytes_read
            data = uploaded.stream.read(n)
            bytes_read += len(data)
            if bytes_read > quota_remaining:
                raise ValueError("quota_exceeded")
            return data

        try:
            with open(enc_path, "wb") as out_f:
                nonce_hex, file_hash = crypto.encrypt_stream(_read_chunk, out_f.write, aes_key)
        except ValueError:
            if os.path.exists(enc_path):
                os.remove(enc_path)
            flash("This upload would exceed your storage quota. Delete some files or empty your trash.", "danger")
            return redirect(url_for("upload"))

        if bytes_read == 0:
            os.remove(enc_path)
            flash("The uploaded file is empty.", "danger")
            return redirect(url_for("upload"))

        file_record = File(
            owner_id=current_user.id,
            original_filename=filename,
            encrypted_filename=encrypted_filename,
            file_size=bytes_read,
            sha256_hash=file_hash,
            nonce=nonce_hex,
        )
        db.session.add(file_record)
        db.session.flush()  # get file_record.id before commit

        owner_pub = crypto.load_public_key(current_user.public_key.encode())
        wrapped_for_owner = crypto.wrap_aes_key(aes_key, owner_pub)
        db.session.add(FilePermission(
            file_id=file_record.id, user_id=current_user.id,
            encrypted_aes_key=wrapped_for_owner, permission="download",
        ))
        db.session.commit()

        log_action(current_user, "upload", file=file_record)
        flash(f'"{filename}" was encrypted and uploaded successfully.', "success")
        return redirect(url_for("my_files"))

    return render_template("upload.html")


@app.route("/my-files")
@login_required
def my_files():
    q = request.args.get("q", "").strip()
    sort = request.args.get("sort", "newest")
    page = max(1, request.args.get("page", 1, type=int))

    query = File.query.filter_by(owner_id=current_user.id, is_trashed=False)
    if q:
        query = query.filter(File.original_filename.ilike(f"%{q}%"))

    if sort == "name":
        query = query.order_by(File.original_filename.asc())
    elif sort == "largest":
        query = query.order_by(File.file_size.desc())
    elif sort == "oldest":
        query = query.order_by(File.created_at.asc())
    else:
        query = query.order_by(File.created_at.desc())

    files, total, pages = paginate(query, page, per_page=10)
    return render_template("my_files.html", files=files, q=q, sort=sort, page=page, pages=pages, total=total)


@app.route("/shared-with-me")
@login_required
def shared_files():
    q = request.args.get("q", "").strip()
    page = max(1, request.args.get("page", 1, type=int))

    query = (
        FilePermission.query.filter_by(user_id=current_user.id)
        .join(File, FilePermission.file_id == File.id)
        .filter(File.owner_id != current_user.id, File.is_trashed.is_(False))
    )
    if q:
        query = query.filter(File.original_filename.ilike(f"%{q}%"))
    query = query.order_by(FilePermission.shared_at.desc())

    perms, total, pages = paginate(query, page, per_page=10)
    return render_template("shared_files.html", perms=perms, q=q, page=page, pages=pages, total=total)


# ---------------------------------------------------------------------------
# Preview, download
# ---------------------------------------------------------------------------

def _unwrap_key_for_user(file, user, password):
    """Loads the user's private key and unwraps this file's AES key.
    Raises ValueError (bad password) or FileNotFoundError (missing key file)."""
    private_key = load_user_private_key(user.private_key_path, password)
    perm = FilePermission.query.filter_by(file_id=file.id, user_id=user.id).first()
    aes_key = crypto.unwrap_aes_key(perm.encrypted_aes_key, private_key)
    return aes_key, perm


def _decrypted_chunks(file, aes_key):
    """Yields decrypted plaintext chunks for `file` without ever holding the
    whole file in memory. Raises InvalidTag mid-stream if any chunk fails
    authentication (each chunk is independently GCM-authenticated, so
    tampering is still caught — just per-chunk instead of whole-file)."""
    enc_path = os.path.join(app.config["ENCRYPTED_FILES_DIR"], file.encrypted_filename)
    with open(enc_path, "rb") as f:
        for chunk in crypto.decrypt_stream(f.read, aes_key, file.nonce):
            yield chunk


def _decrypt_for_user(file, user, password, max_bytes=None):
    """Convenience wrapper for the small cases (text preview, image preview)
    that still need plaintext as one bytes object. Only pulls `max_bytes`
    worth of chunks if given — never buffers a whole large file just to
    preview it. NOT used for full downloads (those stream directly)."""
    aes_key, perm = _unwrap_key_for_user(file, user, password)
    pieces = []
    total = 0
    gen = _decrypted_chunks(file, aes_key)
    try:
        for chunk in gen:
            pieces.append(chunk)
            total += len(chunk)
            if max_bytes is not None and total >= max_bytes:
                break
    finally:
        gen.close()  # ensures the underlying file handle is released now, not at GC time
    return b"".join(pieces), perm


@app.route("/file/<int:file_id>/download", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per minute")
def download(file_id):
    file = db.session.get(File, file_id)
    if not file:
        abort(404)

    allowed, perm_or_reason = user_can_access(file, current_user)
    if not allowed:
        log_action(current_user, "unauthorized_access_attempt", file=file, detail=perm_or_reason)
        flash("You do not have permission to access this file.", "danger")
        abort(403)

    if request.method == "POST":
        password = request.form.get("password", "")
        mode = request.form.get("mode", "download")

        # Unwrapping the key only needs the RSA private key + this file's
        # wrapped AES key — it does NOT touch the (possibly huge) encrypted
        # file on disk, so a wrong password is still rejected instantly.
        try:
            aes_key, perm = _unwrap_key_for_user(file, current_user, password)
        except (ValueError, FileNotFoundError):
            flash("Incorrect password.", "danger")
            return render_template("download_confirm.html", file=file)

        if mode == "preview":
            ext = file.extension()
            PREVIEW_IMAGE_MAX_BYTES = 20 * 1024 * 1024  # don't decrypt huge images just to preview them
            if ext in app.config["PREVIEWABLE_TEXT_EXTENSIONS"]:
                try:
                    # Only pulls enough chunks to cover the preview cap — a
                    # multi-GB text/log file is NOT fully decrypted here.
                    plaintext, _ = _decrypt_for_user(
                        file, current_user, password, max_bytes=app.config["PREVIEW_MAX_BYTES"]
                    )
                except InvalidTag:
                    log_action(current_user, "integrity_failure", file=file)
                    flash("SECURITY ALERT: file integrity check failed — preview blocked.", "danger")
                    return redirect(url_for("dashboard"))
                log_action(current_user, "preview", file=file)
                text = plaintext[: app.config["PREVIEW_MAX_BYTES"]].decode("utf-8", errors="replace")
                truncated = file.file_size > app.config["PREVIEW_MAX_BYTES"]
                return render_template("preview.html", file=file, kind="text", text=text, truncated=truncated)
            elif ext in app.config["PREVIEWABLE_IMAGE_EXTENSIONS"]:
                if file.file_size > PREVIEW_IMAGE_MAX_BYTES:
                    flash("This image is too large to preview inline — download it instead.", "warning")
                    return render_template("download_confirm.html", file=file)
                import base64
                try:
                    plaintext, _ = _decrypt_for_user(file, current_user, password)
                except InvalidTag:
                    log_action(current_user, "integrity_failure", file=file)
                    flash("SECURITY ALERT: file integrity check failed — preview blocked.", "danger")
                    return redirect(url_for("dashboard"))
                log_action(current_user, "preview", file=file)
                mime = "image/jpeg" if ext in ("jpg", "jpeg") else f"image/{ext}"
                b64 = base64.b64encode(plaintext).decode("ascii")
                return render_template("preview.html", file=file, kind="image", data_uri=f"data:{mime};base64,{b64}")
            else:
                flash("This file type doesn't support inline preview — download it instead.", "warning")
                return render_template("download_confirm.html", file=file)

        perm.download_count = (perm.download_count or 0) + 1
        file.download_total = (file.download_total or 0) + 1
        db.session.commit()

        log_action(current_user, "download", file=file)

        def generate():
            try:
                for chunk in _decrypted_chunks(file, aes_key):
                    yield chunk
            except InvalidTag:
                # Headers/response have already started streaming to the
                # browser by this point, so we can't show a flash page —
                # we log it server-side and cut the connection. The
                # browser will show an incomplete/failed download, which
                # is the correct outcome for tampered data.
                log_action(current_user, "integrity_failure", file=file)
                raise

        return Response(
            generate(),
            mimetype="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{file.original_filename}"',
                "Content-Length": str(file.file_size),
            },
        )

    return render_template("download_confirm.html", file=file)

# ---------------------------------------------------------------------------
# Sharing (per-user permissions)
# ---------------------------------------------------------------------------

@app.route("/file/<int:file_id>/share", methods=["GET", "POST"])
@login_required
def share_file(file_id):
    file = db.session.get(File, file_id)
    if not file or file.is_trashed:
        abort(404)
    if file.owner_id != current_user.id:
        log_action(current_user, "unauthorized_share_attempt", file=file)
        abort(403)

    users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
    links = ShareLink.query.filter_by(file_id=file.id).order_by(ShareLink.created_at.desc()).all()

    if request.method == "POST":
        recipient_id = request.form.get("recipient_id", type=int)
        permission_type = request.form.get("permission", "download")
        expires_days = request.form.get("expires_days", type=int)
        max_downloads = request.form.get("max_downloads", type=int)

        recipient = db.session.get(User, recipient_id) if recipient_id else None
        if not recipient:
            flash("Please choose a valid recipient.", "danger")
            return render_template("share_file.html", file=file, users=users, links=links)

        existing = FilePermission.query.filter_by(file_id=file.id, user_id=recipient.id).first()
        if existing:
            flash(f"{recipient.username} already has access to this file.", "warning")
            return redirect(url_for("share_file", file_id=file.id))

        # Owner already holds a permission row (created on upload) which
        # contains an AES key wrapped for the OWNER's public key. We must
        # decrypt it with the owner's private key, then re-wrap it with the
        # recipient's public key. This requires the owner's password.
        owner_password = request.form.get("owner_password", "")
        try:
            owner_private_key = load_user_private_key(current_user.private_key_path, owner_password)
        except (InvalidTag, ValueError):
            flash("Incorrect password — could not authorize sharing.", "danger")
            return render_template("share_file.html", file=file, users=users, links=links)

        owner_perm = FilePermission.query.filter_by(file_id=file.id, user_id=current_user.id).first()
        aes_key = crypto.unwrap_aes_key(owner_perm.encrypted_aes_key, owner_private_key)

        recipient_pub = crypto.load_public_key(recipient.public_key.encode())
        wrapped_for_recipient = crypto.wrap_aes_key(aes_key, recipient_pub)

        new_perm = FilePermission(
            file_id=file.id,
            user_id=recipient.id,
            encrypted_aes_key=wrapped_for_recipient,
            permission=permission_type,
            expires_at=(datetime.utcnow() + timedelta(days=expires_days)) if expires_days else None,
            max_downloads=max_downloads if max_downloads else None,
        )
        db.session.add(new_perm)
        db.session.commit()

        log_action(current_user, "share", file=file, detail=f"shared with {recipient.username}")
        notify(recipient, f'{current_user.username} shared "{file.original_filename}" with you.',
               category="info", link=url_for("shared_files"))
        flash(f'"{file.original_filename}" shared with {recipient.username}.', "success")
        return redirect(url_for("my_files"))

    return render_template("share_file.html", file=file, users=users, links=links)


@app.route("/file/<int:file_id>/revoke/<int:user_id>", methods=["POST"])
@login_required
def revoke(file_id, user_id):
    file = db.session.get(File, file_id)
    if not file or file.owner_id != current_user.id:
        abort(403)
    revoked_user = db.session.get(User, user_id)
    if revoke_access(file, user_id):
        log_action(current_user, "revoke", file=file,
                    detail=f"revoked {revoked_user.username if revoked_user else user_id}")
        if revoked_user:
            notify(revoked_user, f'Your access to "{file.original_filename}" was revoked.', category="warning")
        flash("Access revoked.", "info")
    return redirect(url_for("share_file", file_id=file.id))


# ---------------------------------------------------------------------------
# Public share links (capability URLs — no account required to fetch)
# ---------------------------------------------------------------------------

@app.route("/file/<int:file_id>/link/create", methods=["POST"])
@login_required
def create_share_link(file_id):
    file = db.session.get(File, file_id)
    if not file or file.owner_id != current_user.id:
        abort(403)

    owner_password = request.form.get("owner_password", "")
    label = request.form.get("label", "").strip() or None
    link_password = request.form.get("link_password", "").strip()
    expires_days = request.form.get("link_expires_days", type=int)
    max_downloads = request.form.get("link_max_downloads", type=int)

    try:
        owner_private_key = load_user_private_key(current_user.private_key_path, owner_password)
    except (InvalidTag, ValueError):
        flash("Incorrect password — could not create link.", "danger")
        return redirect(url_for("share_file", file_id=file.id))

    owner_perm = FilePermission.query.filter_by(file_id=file.id, user_id=current_user.id).first()
    aes_key = crypto.unwrap_aes_key(owner_perm.encrypted_aes_key, owner_private_key)

    token = generate_token(app.config["SHARE_LINK_TOKEN_BYTES"])
    salt_hex, wrapped_hex = wrap_key_for_link(aes_key, token)

    link = ShareLink(
        file_id=file.id,
        created_by=current_user.id,
        token=token,
        label=label,
        wrap_salt=salt_hex,
        wrapped_aes_key=wrapped_hex,
        password_hash=generate_password_hash(link_password) if link_password else None,
        expires_at=(datetime.utcnow() + timedelta(days=expires_days)) if expires_days
                   else (datetime.utcnow() + timedelta(days=app.config["SHARE_LINK_DEFAULT_EXPIRY_DAYS"])),
        max_downloads=max_downloads if max_downloads else None,
    )
    db.session.add(link)
    db.session.commit()

    log_action(current_user, "link_create", file=file, detail=token[:8] + "…")
    flash("Public link created. Copy it now — anyone with the link (and password, if set) can access it.", "success")
    return redirect(url_for("share_file", file_id=file.id))


@app.route("/file/<int:file_id>/link/<int:link_id>/revoke", methods=["POST"])
@login_required
def revoke_share_link(file_id, link_id):
    link = db.session.get(ShareLink, link_id)
    if not link or link.created_by != current_user.id or link.file_id != file_id:
        abort(403)
    link.revoked = True
    db.session.commit()
    log_action(current_user, "link_revoke", file=link.file, detail=link.token[:8] + "…")
    flash("Link revoked.", "info")
    return redirect(url_for("share_file", file_id=file_id))


@app.route("/link/<token>", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def public_link(token):
    link = ShareLink.query.filter_by(token=token).first()
    if not link:
        abort(404)
    if link.is_expired():
        return render_template("link_view.html", link=None, expired=True)

    error = None
    if request.method == "POST":
        submitted_password = request.form.get("password", "")
        if not link.check_password(submitted_password):
            error = "Incorrect password."
            log_action(None, "link_access_failed", file=link.file, detail=token[:8] + "…")
        else:
            try:
                aes_key = unwrap_key_for_link(link.wrap_salt, link.wrapped_aes_key, token)
                enc_path = os.path.join(app.config["ENCRYPTED_FILES_DIR"], link.file.encrypted_filename)
                with open(enc_path, "rb") as f:
                    ciphertext = f.read()
                plaintext = crypto.decrypt_file_data(ciphertext, aes_key, link.file.nonce)
                if crypto.sha256_hex(plaintext) != link.file.sha256_hash:
                    raise InvalidTag("integrity mismatch")
            except InvalidTag:
                log_action(None, "integrity_failure", file=link.file, detail=token[:8] + "…")
                return render_template("error.html", code=409, message="Integrity check failed — this file may have been tampered with."), 409

            link.download_count = (link.download_count or 0) + 1
            link.file.download_total = (link.file.download_total or 0) + 1
            db.session.commit()
            log_action(None, "link_download", file=link.file, detail=token[:8] + "…")
            notify(link.creator, f'Your link for "{link.file.original_filename}" was used to download it.',
                   category="info", link=url_for("share_file", file_id=link.file_id))
            return send_file(io.BytesIO(plaintext), as_attachment=True, download_name=link.file.original_filename)

    return render_template("link_view.html", link=link, expired=False, error=error)


# ---------------------------------------------------------------------------
# Trash (soft delete)
# ---------------------------------------------------------------------------

def _purge_old_trash(user):
    cutoff = datetime.utcnow() - timedelta(days=app.config["TRASH_RETENTION_DAYS"])
    stale = File.query.filter(
        File.owner_id == user.id, File.is_trashed.is_(True), File.trashed_at < cutoff,
    ).all()
    for f in stale:
        _permanently_delete(f)


def _permanently_delete(file):
    enc_path = os.path.join(app.config["ENCRYPTED_FILES_DIR"], file.encrypted_filename)
    if os.path.exists(enc_path):
        os.remove(enc_path)
    db.session.delete(file)
    db.session.commit()


@app.route("/file/<int:file_id>/trash", methods=["POST"])
@login_required
def trash_file(file_id):
    file = db.session.get(File, file_id)
    if not file or file.owner_id != current_user.id:
        abort(403)
    file.is_trashed = True
    file.trashed_at = datetime.utcnow()
    db.session.commit()
    log_action(current_user, "trash", file=file)
    flash(f'"{file.original_filename}" moved to trash.', "info")
    return redirect(url_for("my_files"))


@app.route("/file/<int:file_id>/restore", methods=["POST"])
@login_required
def restore_file(file_id):
    file = db.session.get(File, file_id)
    if not file or file.owner_id != current_user.id:
        abort(403)
    file.is_trashed = False
    file.trashed_at = None
    db.session.commit()
    log_action(current_user, "restore", file=file)
    flash(f'"{file.original_filename}" restored.', "success")
    return redirect(url_for("trash"))


@app.route("/file/<int:file_id>/delete-forever", methods=["POST"])
@login_required
def delete_forever(file_id):
    file = db.session.get(File, file_id)
    if not file or file.owner_id != current_user.id:
        abort(403)
    name = file.original_filename
    log_action(current_user, "delete_forever", file=file)
    _permanently_delete(file)
    flash(f'"{name}" permanently deleted.', "info")
    return redirect(url_for("trash"))


@app.route("/trash")
@login_required
def trash():
    _purge_old_trash(current_user)
    files = File.query.filter_by(owner_id=current_user.id, is_trashed=True).order_by(File.trashed_at.desc()).all()
    return render_template("trash.html", files=files, retention_days=app.config["TRASH_RETENTION_DAYS"])


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

@app.route("/notifications")
@login_required
def notifications():
    items = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(50).all()
    return render_template("notifications.html", items=items)


@app.route("/notifications/mark-read", methods=["POST"])
@login_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True})
    return redirect(request.referrer or url_for("dashboard"))


# ---------------------------------------------------------------------------
# Settings — theme, 2FA, storage
# ---------------------------------------------------------------------------

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@app.route("/settings/theme", methods=["POST"])
@login_required
def set_theme():
    theme = request.form.get("theme", "dark")
    theme = "light" if theme == "light" else "dark"
    current_user.theme_preference = theme
    db.session.commit()
    resp = make_response(redirect(request.referrer or url_for("dashboard")))
    resp.set_cookie("theme", theme, max_age=60 * 60 * 24 * 365)
    return resp


@app.route("/settings/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if current_user.totp_enabled:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("settings"))

    if "pending_totp_secret" not in session:
        session["pending_totp_secret"] = generate_totp_secret()

    secret = session["pending_totp_secret"]
    uri = provisioning_uri(secret, current_user.username, app.config["TOTP_ISSUER"])

    if request.method == "POST":
        code = request.form.get("code", "")
        if verify_totp_code(secret, code):
            current_user.totp_secret = secret
            current_user.totp_enabled = True
            backup_codes = generate_backup_codes()
            current_user.set_backup_codes(backup_codes)
            db.session.commit()
            session.pop("pending_totp_secret", None)
            log_action(current_user, "2fa_enabled")
            flash("Two-factor authentication enabled. Save your backup codes somewhere safe.", "success")
            return render_template("backup_codes.html", codes=backup_codes)
        flash("That code didn't match. Double-check your authenticator app and try again.", "danger")

    return render_template("setup_2fa.html", secret=secret, uri=uri)


@app.route("/settings/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    password = request.form.get("password", "")
    if not current_user.check_password(password):
        flash("Incorrect password.", "danger")
        return redirect(url_for("settings"))
    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.totp_backup_codes = None
    db.session.commit()
    log_action(current_user, "2fa_disabled")
    flash("Two-factor authentication disabled.", "info")
    return redirect(url_for("settings"))


@app.route("/settings/2fa/backup-codes/regenerate", methods=["POST"])
@login_required
def regenerate_backup_codes():
    password = request.form.get("password", "")
    if not current_user.check_password(password) or not current_user.totp_enabled:
        flash("Incorrect password.", "danger")
        return redirect(url_for("settings"))
    codes = generate_backup_codes()
    current_user.set_backup_codes(codes)
    db.session.commit()
    log_action(current_user, "2fa_backup_codes_regenerated")
    return render_template("backup_codes.html", codes=codes)


# ---------------------------------------------------------------------------
# Audit logs
# ---------------------------------------------------------------------------

@app.route("/audit-logs")
@login_required
def audit_logs():
    action_filter = request.args.get("action", "").strip()
    page = max(1, request.args.get("page", 1, type=int))

    owned_file_ids = [f.id for f in File.query.filter_by(owner_id=current_user.id).all()]
    query = AuditLog.query.filter(
        (AuditLog.user_id == current_user.id) | (AuditLog.file_id.in_(owned_file_ids))
    )
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    query = query.order_by(AuditLog.timestamp.desc())

    logs, total, pages = paginate(query, page, per_page=25)

    all_actions = sorted({
        row[0] for row in db.session.query(AuditLog.action).filter(
            (AuditLog.user_id == current_user.id) | (AuditLog.file_id.in_(owned_file_ids))
        ).distinct().all()
    })

    return render_template("audit_logs.html", logs=logs, page=page, pages=pages, total=total,
                           action_filter=action_filter, all_actions=all_actions)


@app.route("/audit-logs/export.csv")
@login_required
def export_audit_logs():
    owned_file_ids = [f.id for f in File.query.filter_by(owner_id=current_user.id).all()]
    logs = (
        AuditLog.query.filter(
            (AuditLog.user_id == current_user.id) | (AuditLog.file_id.in_(owned_file_ids))
        )
        .order_by(AuditLog.timestamp.desc())
        .limit(5000)
        .all()
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "user", "action", "file", "ip_address", "detail"])
    for log in logs:
        writer.writerow([log.timestamp.isoformat(), log.username or "", log.action,
                          log.filename or "", log.ip_address or "", log.detail or ""])
    output = make_response(buf.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=audit_logs.csv"
    output.headers["Content-Type"] = "text/csv"
    log_action(current_user, "audit_export")
    return output


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Forbidden — you do not have permission to access this resource."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413, message="File is too large (max 25 GB)."), 413


@app.errorhandler(429)
def rate_limited(e):
    return render_template("error.html", code=429, message="Too many attempts — please slow down and try again shortly."), 429


def init_db():
    # Table creation is now handled by Flask-Migrate ("flask db upgrade"),
    # not here — this just makes sure the non-database folders the app
    # needs exist. See README / setup notes for the one-time migration
    # commands to run against a fresh database.
    os.makedirs(os.path.join(Config.BASE_DIR, "instance"), exist_ok=True)
    os.makedirs(Config.ENCRYPTED_FILES_DIR, exist_ok=True)
    os.makedirs(Config.KEYS_DIR, exist_ok=True)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
