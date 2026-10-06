# SecureShare

A Flask-based encrypted file sharing system built to demonstrate real hybrid
cryptography patterns (RSA-3072 + AES-256-GCM), plus the surrounding product
features a sharing tool actually needs: two-factor auth, public share links,
trash/restore, notifications, quotas, and a full audit trail.

> Portfolio / learning project. Read the "Security notes & limitations"
> section before using this for anything real.

## Features

**Encryption**
- Every file gets a fresh, single-use AES-256-GCM key — never reused.
- The AES key is wrapped (RSA-OAEP, SHA-256) separately for each person who
  can access the file, so the server never stores a usable key, and revoking
  one person's access never requires re-encrypting the file for everyone else.
- SHA-256 integrity check on every decrypt — silent tampering or corruption
  is caught and blocked rather than served.
- Each user's RSA private key is itself encrypted at rest with a key derived
  from their password (PBKDF2-HMAC-SHA256, 480k iterations).

**Sharing**
- Per-user grants with optional expiry dates and download caps.
- One-click revocation.
- **Public capability links** — share a file with someone who has no
  account. The link's own random token doubles as key material (the AES key
  is re-wrapped with a key derived from the token), so possessing the exact
  URL is what grants decryption — the server never persists a plain-text
  copy of that key. Links support an optional password, expiry, and a
  download cap, and can be revoked at any time.

**Account security**
- scrypt password hashing, lockout after repeated failed logins.
- Optional TOTP two-factor authentication with one-time backup codes.
- Rate limiting (Flask-Limiter) on login, registration, downloads, and
  public link access.
- Security headers (CSP, X-Frame-Options, nosniff) on every response.

**File management**
- Drag-and-drop upload with a live progress bar and client-side size checks.
- Inline preview for text and image files — decrypted in memory only, never
  written to disk unencrypted.
- Search, sort, and pagination on file lists.
- Soft-delete/trash with a 30-day retention window and one-click restore.
- Per-user storage quotas with a live usage bar.

**Visibility**
- In-app notifications (a file was shared with you, your access was
  revoked, someone used your public link).
- Full audit log — every login, share, download, revoke, and unauthorized
  attempt — filterable by action, paginated, and exportable to CSV.

**Design**
- Sidebar app layout with light/dark theme toggle (persisted per-user).
- No third-party UI framework — plain CSS custom properties, inline SVG
  icons, a small vanilla-JS file for drag-and-drop and the notification panel.

## Project structure

```
secure-file-sharing/
├── app.py                  # routes
├── config.py                # settings
├── models.py                 # SQLAlchemy models
├── requirements.txt
├── utils/
│   ├── crypto.py              # RSA/AES primitives
│   ├── key_manager.py          # private key at-rest encryption
│   ├── permissions.py           # access control checks
│   ├── audit.py                  # audit log writer
│   ├── two_factor.py              # TOTP + backup codes
│   ├── notifications.py            # in-app notification helper
│   └── share_links.py               # public link key-wrapping
├── templates/                # Jinja2 templates
├── static/
│   ├── css/style.css           # design system
│   └── js/main.js                # drag&drop, notifications, theme
├── encrypted_files/          # encrypted blobs live here (gitignored)
├── keys/                     # encrypted private keys (gitignored)
└── instance/                 # SQLite database (gitignored)
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Visit `http://127.0.0.1:5000`. The database and folders under
`encrypted_files/`, `keys/`, and `instance/` are created automatically on
first run.

## Security notes & limitations

This project demonstrates real cryptographic patterns, but a few things
are simplified on purpose for a learning/portfolio context:

- **No password reset flow.** Because private keys are encrypted with the
  user's password, a forgotten password means the private key — and every
  file only shared to that account — is unrecoverable. A production system
  would need a key-escrow or re-encryption strategy to support resets safely.
- **SQLite** is used for simplicity. Swap `SQLALCHEMY_DATABASE_URI` in
  `config.py` for Postgres/MySQL in any real deployment.
- **`SECRET_KEY`** falls back to a random value generated at boot if the
  `SECRET_KEY` environment variable isn't set — fine for local use, but set
  it explicitly (and keep it stable) in production, or every restart
  invalidates all sessions.
- **Rate limiting** uses in-memory storage (`memory://`), which resets on
  restart and doesn't share state across multiple app processes/workers —
  use Redis in production (`RATELIMIT_STORAGE_URI` in `config.py`).
- **File size limit** is 25 MB (`MAX_CONTENT_LENGTH` in `config.py`).
