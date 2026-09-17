"""Small, deployable account store for the hosted API.

The store uses SQLite so the reference deployment has no mandatory database
service. Put ``PKGGUARD_ACCOUNT_DB`` on persistent storage in production.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional


SESSION_DAYS = 30


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(os.environ.get("PKGGUARD_ACCOUNT_DB", "pkgguard-accounts.sqlite3"))
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            plan TEXT NOT NULL DEFAULT 'free',
            created_at TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            account_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(account_id) REFERENCES accounts(id)
        )"""
    )
    connection.commit()
    return connection


def _password_hash(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return f"{salt.hex()}:{digest.hex()}"


def _password_matches(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        candidate = _password_hash(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
        return hmac.compare_digest(candidate, digest_hex)
    except (ValueError, TypeError):
        return False


def create_account(email: str, password: str) -> int:
    normalized = email.strip().lower()
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    connection = _connect()
    try:
        cursor = connection.execute(
            "INSERT INTO accounts(email, password_hash, created_at) VALUES (?, ?, ?)",
            (normalized, _password_hash(password), datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
        return int(cursor.lastrowid)
    except sqlite3.IntegrityError as error:
        raise ValueError("An account with that email already exists.") from error
    finally:
        connection.close()


def create_session(email: str, password: str) -> str:
    connection = _connect()
    account = connection.execute(
        "SELECT * FROM accounts WHERE email = ?", (email.strip().lower(),)
    ).fetchone()
    if account is None or not _password_matches(password, account["password_hash"]):
        connection.close()
        raise ValueError("Invalid email or password.")
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    connection.execute(
        "INSERT INTO sessions(token_hash, account_id, expires_at) VALUES (?, ?, ?)",
        (token_hash, account["id"], expires.isoformat()),
    )
    connection.commit()
    connection.close()
    return token


def account_for_session(token: str) -> Optional[sqlite3.Row]:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    connection = _connect()
    row = connection.execute(
        """SELECT accounts.* FROM sessions
           JOIN accounts ON accounts.id = sessions.account_id
           WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
        (token_hash, datetime.now(timezone.utc).isoformat()),
    ).fetchone()
    connection.close()
    return row


def update_subscription(
    email: str,
    customer_id: str,
    subscription_id: str,
    plan: str,
) -> None:
    connection = _connect()
    connection.execute(
        """UPDATE accounts SET stripe_customer_id = ?, stripe_subscription_id = ?, plan = ?
           WHERE email = ?""",
        (customer_id, subscription_id, plan, email.strip().lower()),
    )
    connection.commit()
    connection.close()


def account_for_subscription(subscription_id: str):
    """Find the account attached to a Stripe subscription for webhook events."""
    if not subscription_id:
        return None
    connection = _connect()
    row = connection.execute(
        "SELECT * FROM accounts WHERE stripe_subscription_id = ?",
        (subscription_id,),
    ).fetchone()
    connection.close()
    return row
