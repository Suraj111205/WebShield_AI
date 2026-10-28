"""
WebShield AI Database & Authentication Management
Supports PostgreSQL (when configured and active) with seamless fallback to SQLite.
"""

import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple
from dotenv import load_dotenv

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, ForeignKey, event
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

DB_DIR = BASE_DIR / "database"
DB_DIR.mkdir(exist_ok=True)
SQLITE_DB_PATH = DB_DIR / "webshield.db"

# Determine database engine
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

engine = None
db_type = "sqlite"

import socket
from urllib.parse import urlparse

def is_db_server_alive(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        with socket.create_connection((host, port), timeout=0.3):
            return True
    except Exception:
        return False

if DATABASE_URL and DATABASE_URL.startswith("postgresql") and is_db_server_alive(DATABASE_URL):
    try:
        test_engine = create_engine(
            DATABASE_URL,
            connect_args={"connect_timeout": 2},
            pool_pre_ping=True
        )
        with test_engine.connect():
            pass
        engine = test_engine
        db_type = "postgresql"
        print(f"[Database] Connected to PostgreSQL: {DATABASE_URL.split('@')[-1]}")
    except Exception as e:
        print(f"[Database] PostgreSQL connection error ({e}). Falling back to SQLite.")
else:
    if DATABASE_URL and DATABASE_URL.startswith("postgresql"):
        print("[Database] PostgreSQL server not reachable on port 5432. Falling back to SQLite.")


if engine is None:
    sqlite_url = f"sqlite:///{SQLITE_DB_PATH.as_posix()}"
    engine = create_engine(
        sqlite_url,
        connect_args={"check_same_thread": False}
    )
    db_type = "sqlite"
    print(f"[Database] Active database: SQLite at {SQLITE_DB_PATH}")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# =====================================================================
# Models
# =====================================================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), default="Security Analyst")
    email = Column(String(150), unique=True, index=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    scan_count = Column(Integer, default=0)

    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("ScanLog", back_populates="user")


class UserSession(Base):
    __tablename__ = "user_sessions"

    token = Column(String(64), primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="sessions")


class GuestQuota(Base):
    __tablename__ = "guest_quotas"

    identifier = Column(String(120), primary_key=True, index=True)  # IP or client cookie
    scan_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_scan_at = Column(DateTime, default=datetime.utcnow)


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    target_url = Column(Text, nullable=False)
    scan_type = Column(String(50), default="Full")
    vulnerabilities_found = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scans")


# Create tables if not present
Base.metadata.create_all(bind=engine)


# =====================================================================
# Password Security (NIST PBKDF2 with Salt)
# =====================================================================

def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 rounds and random salt."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()
    return f"{salt}${key}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against salt$hash string."""
    try:
        salt, key = hashed_password.split("$", 1)
        expected_key = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            100_000
        ).hex()
        return secrets.compare_digest(key, expected_key)
    except Exception:
        return False


# =====================================================================
# Database Operations
# =====================================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$"
)


def validate_email_address(email: str) -> Tuple[bool, str]:
    """Validate format and structure of email address."""
    if not email or not isinstance(email, str):
        return False, "Email address is required."

    clean = email.strip().lower()
    if len(clean) > 150:
        return False, "Email address cannot exceed 150 characters."

    if not EMAIL_REGEX.match(clean) or ".." in clean:
        return False, "Please enter a valid email address (e.g., name@domain.com)."

    parts = clean.split("@")
    if len(parts) != 2:
        return False, "Email must contain exactly one '@' symbol."

    username, domain = parts
    if not username or not domain:
        return False, "Email must include both a username and a domain name."

    domain_parts = domain.split(".")
    if len(domain_parts) < 2 or len(domain_parts[-1]) < 2:
        return False, "Email domain must include a valid top-level domain (e.g., .com, .org, .edu)."

    return True, ""


def create_user(email: str, password: str, name: str = "") -> Tuple[Optional[User], str]:
    """Register a new user with strict email validation. Returns (User, error_message)."""
    valid, err_msg = validate_email_address(email)
    if not valid:
        return None, err_msg

    email_clean = email.strip().lower()
    if len(password) < 6:
        return None, "Password must be at least 6 characters long."

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email_clean).first()
        if existing:
            return None, "An account with this email already exists."

        user = User(
            name=name.strip() or email_clean.split("@")[0].capitalize(),
            email=email_clean,
            password_hash=hash_password(password),
            created_at=datetime.utcnow(),
            scan_count=0
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user, ""
    except Exception as e:
        db.rollback()
        return None, f"Database error: {str(e)}"
    finally:
        db.close()


def authenticate_user(email: str, password: str) -> Optional[User]:
    """Verify credentials and return user object if valid."""
    email_clean = email.strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email_clean).first()
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user
    finally:
        db.close()


def create_user_session(user_id: int, days_valid: int = 14) -> str:
    """Generate a cryptographic session token for authenticated user."""
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(days=days_valid)
    db = SessionLocal()
    try:
        session = UserSession(token=token, user_id=user_id, expires_at=expires)
        db.add(session)
        db.commit()
        return token
    finally:
        db.close()


def get_user_by_token(token: str) -> Optional[User]:
    """Retrieve user attached to valid unexpired session token."""
    if not token:
        return None
    db = SessionLocal()
    try:
        session = db.query(UserSession).filter(
            UserSession.token == token,
            UserSession.expires_at > datetime.utcnow()
        ).first()
        if not session:
            return None
        user = db.query(User).filter(User.id == session.user_id).first()
        return user
    finally:
        db.close()


def revoke_session(token: str) -> bool:
    """Log out / delete session token."""
    if not token:
        return False
    db = SessionLocal()
    try:
        deleted = db.query(UserSession).filter(UserSession.token == token).delete()
        db.commit()
        return deleted > 0
    finally:
        db.close()


# =====================================================================
# Quota & Scan Tracking
# =====================================================================

GUEST_SCAN_LIMIT = 2

def get_guest_quota(identifier: str) -> dict:
    """Get scan counts and remaining quota for unauthenticated guest."""
    db = SessionLocal()
    try:
        record = db.query(GuestQuota).filter(GuestQuota.identifier == identifier).first()
        used = record.scan_count if record else 0
        remaining = max(0, GUEST_SCAN_LIMIT - used)
        return {
            "used": used,
            "remaining": remaining,
            "limit": GUEST_SCAN_LIMIT,
            "is_unlimited": False,
            "can_scan": remaining > 0
        }
    finally:
        db.close()


def record_scan_usage(identifier: str, user: Optional[User] = None, target_url: str = "", vuln_count: int = 0) -> dict:
    """
    Increment scan usage.
    If user is authenticated: unlimited, increments user scan count and creates scan log.
    If guest: increments guest quota record up to or past limit.
    """
    db = SessionLocal()
    try:
        if user:
            # Update user scan counter
            db_user = db.query(User).filter(User.id == user.id).first()
            if db_user:
                db_user.scan_count = (db_user.scan_count or 0) + 1
            
            # Log scan
            log = ScanLog(
                user_id=user.id,
                target_url=target_url,
                scan_type="Full",
                vulnerabilities_found=vuln_count
            )
            db.add(log)
            db.commit()

            return {
                "authenticated": True,
                "is_unlimited": True,
                "used": db_user.scan_count if db_user else 1,
                "remaining": "unlimited",
                "can_scan": True
            }
        else:
            # Guest quota update
            record = db.query(GuestQuota).filter(GuestQuota.identifier == identifier).first()
            if not record:
                record = GuestQuota(identifier=identifier, scan_count=1, last_scan_at=datetime.utcnow())
                db.add(record)
            else:
                record.scan_count += 1
                record.last_scan_at = datetime.utcnow()

            # Also log anonymous scan
            log = ScanLog(
                user_id=None,
                target_url=target_url,
                scan_type="Guest Scan",
                vulnerabilities_found=vuln_count
            )
            db.add(log)
            db.commit()

            used = record.scan_count
            remaining = max(0, GUEST_SCAN_LIMIT - used)
            return {
                "authenticated": False,
                "is_unlimited": False,
                "used": used,
                "remaining": remaining,
                "limit": GUEST_SCAN_LIMIT,
                "can_scan": remaining > 0
            }
    finally:
        db.close()


def reset_guest_quotas():
    """Reset all guest scan counts so server restart or test refresh starts fresh with full scans."""
    db = SessionLocal()
    try:
        db.query(GuestQuota).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def reset_quota_for_identifier(identifier: str):
    """Reset guest quota for a specific client identifier."""
    if not identifier:
        return
    db = SessionLocal()
    try:
        db.query(GuestQuota).filter(GuestQuota.identifier == identifier).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


# Reset guest quotas on startup so restarting or reloading the server clears previous guest counts
reset_guest_quotas()

