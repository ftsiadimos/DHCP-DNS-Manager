"""Persistent SQLite settings store via SQLAlchemy.

Sensitive fields (kea_password, rndc_key, tsig_key_secret) are encrypted at rest
using Fernet symmetric encryption (see app/crypto.py).
"""

import os
from werkzeug.security import generate_password_hash, check_password_hash
from app.db import engine, SessionLocal, Base
from app.models import Setting, User, Zone
from app.crypto import SENSITIVE_KEYS, encrypt, decrypt

DEFAULTS = {
    "kea_api_url": "http://localhost:8000",
    "kea_user": "",
    "kea_password": "",
    "dns_server": "127.0.0.1",
    "dns_port": 53,
    "stats_port": 8053,
    "rndc_host": "127.0.0.1",
    "rndc_port": 953,
    "rndc_bin": "",
    "rndc_key": "",
    "tsig_key_name": "rndc-key",
    "tsig_key_secret": "",
    "tsig_key_algorithm": "hmac-sha256",
    "default_zone": "example.com",
    "default_reverse_zone": "168.192.in-addr.arpa",
    "default_ttl": 3600,
    "disable_login": "false",
}

BOOL_KEYS = {"disable_login"}
INT_KEYS = {"dns_port", "rndc_port", "default_ttl", "stats_port"}


def init_db():
    """Ensure DB tables exist and seed defaults on first run."""
    Base.metadata.create_all(engine)
    with SessionLocal() as session:
        if not session.query(Setting).first():
            for key, value in DEFAULTS.items():
                stored = encrypt(str(value)) if key in SENSITIVE_KEYS else str(value)
                session.add(Setting(key=key, value=stored))
            session.commit()

        admin = session.query(User).filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                password_hash=generate_password_hash("admin"),
                is_admin=True,
            )
            session.add(admin)
            session.commit()

        # Seed zone list from defaults if completely empty
        if not session.query(Zone).first():
            fwd = session.query(Setting).filter_by(key="default_zone").first()
            rev = session.query(Setting).filter_by(key="default_reverse_zone").first()
            if fwd and fwd.value and fwd.value != "example.com":
                session.add(Zone(name=fwd.value.strip().lower().rstrip("."),
                                 zone_type="forward", description="Default forward zone"))
            if rev and rev.value and rev.value != "168.192.in-addr.arpa":
                session.add(Zone(name=rev.value.strip().lower().rstrip("."),
                                 zone_type="reverse", description="Default reverse zone"))
            session.commit()


def load_settings():
    """Load settings from SQLite, decrypting sensitive fields."""
    init_db()
    data = dict(DEFAULTS)
    with SessionLocal() as session:
        for row in session.query(Setting).all():
            value = decrypt(row.value) if row.key in SENSITIVE_KEYS else row.value
            if row.key in INT_KEYS:
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    value = DEFAULTS.get(row.key, value)
            elif row.key in BOOL_KEYS:
                value = value.lower() in ("true", "1", "yes")
            data[row.key] = value
    return data


def save_settings(settings):
    """Save settings to SQLite, encrypting sensitive fields. No JSON file is written."""
    init_db()
    with SessionLocal() as session:
        for key, value in settings.items():
            stored = encrypt(str(value)) if key in SENSITIVE_KEYS else str(value)
            entry = session.get(Setting, key)
            if entry:
                entry.value = stored
            else:
                session.add(Setting(key=key, value=stored))
        session.commit()


def get_user_by_username(username):
    with SessionLocal() as session:
        return session.query(User).filter_by(username=username).first()


def create_user(username, password, is_admin=False):
    init_db()
    with SessionLocal() as session:
        user = get_user_by_username(username)
        if user:
            return user

        user = User(username=username, password_hash=generate_password_hash(password), is_admin=is_admin)
        session.add(user)
        session.commit()
        return user


def verify_user(username, password):
    user = get_user_by_username(username)
    if user and check_password_hash(user.password_hash, password):
        return user
    return None


# ── Zone list ────────────────────────────────────────────────

def list_zones():
    """Return all stored zones ordered by name."""
    init_db()
    with SessionLocal() as session:
        return [
            {"id": z.id, "name": z.name, "zone_type": z.zone_type, "description": z.description}
            for z in session.query(Zone).order_by(Zone.name).all()
        ]


def add_zone(name, zone_type="forward", description=""):
    """Add a zone. Returns (zone_dict, error_str)."""
    init_db()
    name = name.strip().lower().rstrip(".")
    if not name:
        return None, "Zone name cannot be empty."
    with SessionLocal() as session:
        if session.query(Zone).filter_by(name=name).first():
            return None, f"Zone '{name}' already exists."
        z = Zone(name=name, zone_type=zone_type, description=description)
        session.add(z)
        session.commit()
        return {"id": z.id, "name": z.name, "zone_type": z.zone_type, "description": z.description}, None


def delete_zone(zone_id):
    """Delete a zone by id. Returns error string or None."""
    init_db()
    with SessionLocal() as session:
        z = session.get(Zone, zone_id)
        if not z:
            return "Zone not found."
        session.delete(z)
        session.commit()
    return None
