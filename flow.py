"""
Flow — single-file FastAPI app.

Per push, for each selected source ad unit:
  1) Push the user's saved /networks credentials to AdMob as AdUnitMappings
     on the source ad unit (so they can be replicated).
  2) Create N labeled tier ad units (named per-tier with the eCPM).
  3) Replicate every 3P AdUnitMapping from the source onto each tier.
  4) Create ONE mediation group in a SINGLE create call:
       - targeting:  [source, tier_1, ..., tier_N]
       - waterfall:  N MANUAL AdMob Network lines at descending tier eCPMs
       - bidding:    AdMob Network LIVE + LIVE lines for each replicated
                     third-party network
  5) Read the group back and report what AdMob actually persisted.

ADDITIONAL DEPENDENCY (install before running):
    pip install cryptography
"""
from __future__ import annotations

import os

# IMPORTANT: must be set BEFORE importing google_auth_oauthlib / oauthlib.
# Google often returns scopes in a different order than requested (especially
# when `include_granted_scopes=true`), which makes oauthlib raise
# `Warning: Scope has changed from ... to ...` and abort the token exchange.
# Relaxing this lets the callback succeed even when scopes are reordered or
# Google grants an extra one (e.g. openid getting merged in).
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")
# Permit http://localhost during local development so oauthlib doesn't reject
# the non-HTTPS redirect URI.
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")

import json
import random
import string
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Tuple

# Force unbuffered stdout so _log() messages appear in the terminal in real
# time. Some Windows/PowerShell setups (and PyCharm's "Run" console) buffer
# stdout in big chunks even when print() is called with flush=True, which
# makes long-running pushes look like they've hung.
try:
    sys.stdout.reconfigure(line_buffering=True, write_through=True)
    sys.stderr.reconfigure(line_buffering=True, write_through=True)
except (AttributeError, OSError):
    pass
os.environ.setdefault("PYTHONUNBUFFERED", "1")

import requests
import uvicorn
from fastapi import APIRouter, Body, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build, build_from_document
from googleapiclient.errors import HttpError
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text,
    create_engine,
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker
from starlette.middleware.sessions import SessionMiddleware


# ============================================================================
# CONFIG
# ============================================================================
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/auth/callback"
    admob_publisher_id: str = ""
    secret_key: str = "change-me-in-env"
    database_url: str = "sqlite:///./admob_tool.db"
    # Bind to "localhost" (not "127.0.0.1") so that the session cookie set on
    # the OAuth redirect URI (which defaults to http://localhost:8000/...)
    # is sent back on the callback. Mixing the two hostnames causes the
    # callback to lose request.session["oauth_state"] and fail with
    # "Invalid OAuth callback (state mismatch)".
    host: str = "localhost"
    port: int = 8000
    debug: bool = True
    # Security. In production (HTTPS, e.g. Cloud Run) set cookie_secure=true so
    # the session cookie is only ever sent over HTTPS. Keep false for local
    # http://localhost dev. `secret_key` MUST be a strong random value in
    # production — it both signs sessions AND derives the AES-256 data key, so
    # a weak/default value compromises every encrypted token. Startup refuses
    # to run with a weak key unless debug=true.
    cookie_secure: bool = False
    oauth_scopes: list[str] = [
        "https://www.googleapis.com/auth/admob.readonly",
        "https://www.googleapis.com/auth/admob.report",
        "https://www.googleapis.com/auth/admob.monetization",
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ]


settings = Settings()
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


# ============================================================================
# STEP LOGGER  (timestamps + flush so the console reflects progress in real
# time, even when one API call is taking a long time). Also tees to
# `flow.log` next to flow.py so you have a file to inspect if the terminal
# is buffering or you can't see the console.
# ============================================================================
_LOG_FILE = Path(__file__).resolve().parent / "flow.log"

# Open flow.log once for the whole run (truncates at start) and keep the
# handle open — avoids an open()/close() syscall on every _log() line, which
# adds up to hundreds of them during a long push.
try:
    _LOG_FH = _LOG_FILE.open("w", encoding="utf-8")
    _LOG_FH.write(f"=== flow.py started "
                  f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    _LOG_FH.flush()
except Exception:
    _LOG_FH = None


def _log(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    if _LOG_FH is not None:
        try:
            _LOG_FH.write(line + "\n")
            _LOG_FH.flush()
        except Exception:
            pass


def _timed(label: str, fn):
    """Run fn(), log the elapsed time, return its result. On exception,
    log the failure and re-raise."""
    start = time.time()
    _log(f"  -> {label} ...")
    try:
        result = fn()
        elapsed = time.time() - start
        _log(f"     {label} OK ({elapsed:.2f}s)")
        return result
    except Exception as e:
        elapsed = time.time() - start
        _log(f"     {label} FAILED after {elapsed:.2f}s: {type(e).__name__}: {e}")
        raise


# ============================================================================
# WATERFALL FORMULA  (tweak constants to change calculation)
# ============================================================================
# Per-tier multipliers applied to the BASE eCPM (last-7-day average).
# V1 = top of waterfall (highest eCPM), V10 = bottom. Pick the first N
# multipliers when the user chooses N tiers.
WATERFALL_TIER_MULTIPLIERS = [
    5.5,    # V1 (top)
    4.0,    # V2
    3.3,    # V3
    2.75,   # V4
    2.25,   # V5
    1.9,    # V6
    1.55,   # V7
    1.3,    # V8
    1.15,   # V9
    0.85,   # V10 (bottom)
]
# Clamp every tier eCPM to this range — AdMob mediation hard limits.
WATERFALL_MIN_ECPM = 0.2
WATERFALL_MAX_ECPM = 1000.0
WATERFALL_DEFAULT_LINES = 10  # default = max (use all V1..V10 multipliers)
WATERFALL_MAX_LINES = len(WATERFALL_TIER_MULTIPLIERS)  # 10


COMMON_COUNTRIES = [
    {"code": "US", "name": "United States"}, {"code": "GB", "name": "United Kingdom"},
    {"code": "DE", "name": "Germany"}, {"code": "FR", "name": "France"},
    {"code": "JP", "name": "Japan"}, {"code": "KR", "name": "South Korea"},
    {"code": "CA", "name": "Canada"}, {"code": "AU", "name": "Australia"},
    {"code": "BR", "name": "Brazil"}, {"code": "MX", "name": "Mexico"},
    {"code": "IN", "name": "India"}, {"code": "ID", "name": "Indonesia"},
    {"code": "PK", "name": "Pakistan"}, {"code": "BD", "name": "Bangladesh"},
    {"code": "PH", "name": "Philippines"}, {"code": "VN", "name": "Vietnam"},
    {"code": "TH", "name": "Thailand"}, {"code": "MY", "name": "Malaysia"},
    {"code": "SG", "name": "Singapore"}, {"code": "HK", "name": "Hong Kong"},
    {"code": "TW", "name": "Taiwan"}, {"code": "CN", "name": "China"},
    {"code": "SA", "name": "Saudi Arabia"}, {"code": "AE", "name": "United Arab Emirates"},
    {"code": "EG", "name": "Egypt"}, {"code": "TR", "name": "Turkey"},
    {"code": "RU", "name": "Russia"}, {"code": "ES", "name": "Spain"},
    {"code": "IT", "name": "Italy"}, {"code": "NL", "name": "Netherlands"},
    {"code": "SE", "name": "Sweden"}, {"code": "NO", "name": "Norway"},
    {"code": "PL", "name": "Poland"}, {"code": "IR", "name": "Iran"},
    {"code": "IQ", "name": "Iraq"}, {"code": "ZA", "name": "South Africa"},
    {"code": "NG", "name": "Nigeria"}, {"code": "KE", "name": "Kenya"},
    {"code": "AR", "name": "Argentina"}, {"code": "CL", "name": "Chile"},
    {"code": "CO", "name": "Colombia"}, {"code": "PE", "name": "Peru"},
    {"code": "NZ", "name": "New Zealand"}, {"code": "IE", "name": "Ireland"},
    {"code": "CH", "name": "Switzerland"}, {"code": "AT", "name": "Austria"},
    {"code": "BE", "name": "Belgium"}, {"code": "DK", "name": "Denmark"},
    {"code": "FI", "name": "Finland"}, {"code": "PT", "name": "Portugal"},
    # --- Middle East ---
    {"code": "KW", "name": "Kuwait"}, {"code": "QA", "name": "Qatar"},
    {"code": "OM", "name": "Oman"}, {"code": "BH", "name": "Bahrain"},
    {"code": "JO", "name": "Jordan"}, {"code": "LB", "name": "Lebanon"},
    {"code": "YE", "name": "Yemen"}, {"code": "SY", "name": "Syria"},
    {"code": "PS", "name": "Palestine"}, {"code": "IL", "name": "Israel"},
    # --- North Africa & Africa ---
    {"code": "MA", "name": "Morocco"}, {"code": "DZ", "name": "Algeria"},
    {"code": "TN", "name": "Tunisia"}, {"code": "LY", "name": "Libya"},
    {"code": "SD", "name": "Sudan"}, {"code": "TZ", "name": "Tanzania"},
    {"code": "GH", "name": "Ghana"}, {"code": "UG", "name": "Uganda"},
    {"code": "ET", "name": "Ethiopia"}, {"code": "CI", "name": "Côte d'Ivoire"},
    {"code": "SN", "name": "Senegal"}, {"code": "CM", "name": "Cameroon"},
    {"code": "ZM", "name": "Zambia"}, {"code": "ZW", "name": "Zimbabwe"},
    {"code": "AO", "name": "Angola"}, {"code": "MZ", "name": "Mozambique"},
    {"code": "RW", "name": "Rwanda"}, {"code": "ML", "name": "Mali"},
    {"code": "MG", "name": "Madagascar"}, {"code": "BF", "name": "Burkina Faso"},
    {"code": "BJ", "name": "Benin"}, {"code": "BW", "name": "Botswana"},
    {"code": "MU", "name": "Mauritius"},
    # --- Central / South / Southeast Asia ---
    {"code": "AZ", "name": "Azerbaijan"}, {"code": "KZ", "name": "Kazakhstan"},
    {"code": "UZ", "name": "Uzbekistan"}, {"code": "GE", "name": "Georgia"},
    {"code": "AM", "name": "Armenia"}, {"code": "KG", "name": "Kyrgyzstan"},
    {"code": "TJ", "name": "Tajikistan"}, {"code": "TM", "name": "Turkmenistan"},
    {"code": "AF", "name": "Afghanistan"}, {"code": "MM", "name": "Myanmar (Burma)"},
    {"code": "KH", "name": "Cambodia"}, {"code": "LA", "name": "Laos"},
    {"code": "NP", "name": "Nepal"}, {"code": "LK", "name": "Sri Lanka"},
    {"code": "MN", "name": "Mongolia"}, {"code": "BN", "name": "Brunei"},
    {"code": "BT", "name": "Bhutan"}, {"code": "MV", "name": "Maldives"},
    # --- Europe ---
    {"code": "CZ", "name": "Czechia"}, {"code": "GR", "name": "Greece"},
    {"code": "HU", "name": "Hungary"}, {"code": "RO", "name": "Romania"},
    {"code": "BG", "name": "Bulgaria"}, {"code": "HR", "name": "Croatia"},
    {"code": "RS", "name": "Serbia"}, {"code": "SK", "name": "Slovakia"},
    {"code": "SI", "name": "Slovenia"}, {"code": "LT", "name": "Lithuania"},
    {"code": "LV", "name": "Latvia"}, {"code": "EE", "name": "Estonia"},
    {"code": "UA", "name": "Ukraine"}, {"code": "BY", "name": "Belarus"},
    {"code": "IS", "name": "Iceland"}, {"code": "LU", "name": "Luxembourg"},
    {"code": "CY", "name": "Cyprus"}, {"code": "MT", "name": "Malta"},
    {"code": "AL", "name": "Albania"}, {"code": "MK", "name": "North Macedonia"},
    {"code": "BA", "name": "Bosnia & Herzegovina"}, {"code": "MD", "name": "Moldova"},
    # --- Latin America & Caribbean ---
    {"code": "EC", "name": "Ecuador"}, {"code": "VE", "name": "Venezuela"},
    {"code": "BO", "name": "Bolivia"}, {"code": "PY", "name": "Paraguay"},
    {"code": "UY", "name": "Uruguay"}, {"code": "GT", "name": "Guatemala"},
    {"code": "CR", "name": "Costa Rica"}, {"code": "PA", "name": "Panama"},
    {"code": "DO", "name": "Dominican Republic"}, {"code": "HN", "name": "Honduras"},
    {"code": "SV", "name": "El Salvador"}, {"code": "NI", "name": "Nicaragua"},
    {"code": "PR", "name": "Puerto Rico"}, {"code": "JM", "name": "Jamaica"},
    {"code": "TT", "name": "Trinidad & Tobago"},
    # --- Oceania ---
    {"code": "FJ", "name": "Fiji"}, {"code": "PG", "name": "Papua New Guinea"},
]
FLOOR_TYPES = ["ALL_PRICES", "PREMIUM_ONLY", "CUSTOM"]


# ============================================================================
# 3RD-PARTY NETWORK CATALOG
# ============================================================================
NETWORK_CATALOG = [
    {
        "code": "ADMOB",
        "name": "AdMob Network",
        "admob_source_id": "5450213213286189855",
        "supports_bidding": False,
        "app_fields": [],
        "ad_unit_fields": [],
        "internal_only": True,
    },
    {
        "code": "META",
        "name": "Meta",
        "admob_source_id": "10568273599589928883",
        "admob_bidding_source_id": "11198165126854996598",
        "supports_bidding": True,
        "supports_formats": ["BANNER", "INTERSTITIAL", "NATIVE", "REWARDED", "APP_OPEN"],
        "app_fields": [],
        "ad_unit_fields": [
            {"key": "placement_id", "label": "Placement ID", "type": "text",
             "admob_key": "placement_id",
             "help": "From Meta Monetization Manager → Placements"},
        ],
    },
    {
        "code": "APPLOVIN",
        "name": "AppLovin",
        "admob_source_id": "1063618907739174004",
        "admob_bidding_source_id": "1328079684332308356",
        "supports_bidding": True,
        "supports_formats": ["BANNER", "INTERSTITIAL", "NATIVE", "REWARDED",
                             "REWARDED_INTERSTITIAL", "APP_OPEN"],
        "app_fields": [
            {"key": "sdk_key", "label": "SDK Key", "type": "text",
             "admob_key": "sdk_key",
             "help": "AppLovin dashboard → Account → Keys"},
        ],
        "ad_unit_fields": [
            {"key": "zone_id", "label": "Zone ID", "type": "text",
             "admob_key": "zone_id",
             "help": "AppLovin dashboard → MAX → Ad Units"},
        ],
    },
    {
        "code": "UNITY",
        "name": "Unity",
        "admob_source_id": "4970775877303683148",
        "admob_bidding_source_id": "7069338991535737586",
        "supports_bidding": True,
        "supports_formats": ["BANNER", "INTERSTITIAL", "REWARDED",
                             "REWARDED_INTERSTITIAL", "APP_OPEN"],
        "app_fields": [
            {"key": "game_id", "label": "Game ID", "type": "text",
             "admob_key": "game_id",
             "help": "Unity dashboard → Operate → Settings → Project ID"},
        ],
        "ad_unit_fields": [
            {"key": "placement_id", "label": "Placement ID", "type": "text",
             "admob_key": "placement_id",
             "help": "Unity dashboard → Operate → Placements"},
        ],
    },
    {
        "code": "IRONSOURCE",
        "name": "ironSource",
        "admob_source_id": "6925240245545091930",
        "admob_bidding_source_id": "1643326773739866623",
        "supports_bidding": True,
        "supports_formats": ["BANNER", "INTERSTITIAL", "REWARDED", "APP_OPEN"],
        "app_fields": [
            {"key": "app_key", "label": "App Key", "type": "text",
             "admob_key": "app_key",
             "help": "ironSource dashboard → My Apps"},
        ],
        "ad_unit_fields": [
            {"key": "instance_id", "label": "Instance ID", "type": "text",
             "admob_key": "instance_id",
             "help": "ironSource dashboard → Setup → Instance"},
        ],
    },
    {
        "code": "MINTEGRAL",
        "name": "Mintegral",
        "admob_source_id": "1357746574408896200",
        "admob_bidding_source_id": "6250601289653372374",
        "supports_bidding": True,
        "supports_formats": ["BANNER", "INTERSTITIAL", "NATIVE", "REWARDED",
                             "REWARDED_INTERSTITIAL", "APP_OPEN"],
        "app_fields": [
            {"key": "app_id", "label": "App ID", "type": "text",
             "admob_key": "app_id",
             "help": "Mintegral dashboard → Apps"},
            {"key": "app_key", "label": "App Key", "type": "text",
             "admob_key": "app_key",
             "help": "Mintegral dashboard → Apps"},
        ],
        "ad_unit_fields": [
            {"key": "placement_id", "label": "Placement ID", "type": "text",
             "admob_key": "placement_id",
             "help": "Mintegral dashboard → Ad Placement"},
            {"key": "unit_id", "label": "Unit ID", "type": "text",
             "admob_key": "unit_id",
             "help": "Mintegral dashboard → Ad Placement → Unit"},
        ],
    },
    {
        "code": "PANGLE",
        "name": "Pangle",
        "admob_source_id": "4069896914521993236",
        "admob_bidding_source_id": "3525379893916449117",
        "supports_bidding": True,
        "supports_formats": ["BANNER", "INTERSTITIAL", "NATIVE", "REWARDED",
                             "REWARDED_INTERSTITIAL", "APP_OPEN"],
        "app_fields": [
            {"key": "app_id", "label": "App ID", "type": "text",
             "admob_key": "app_id",
             "help": "Pangle dashboard → App management"},
        ],
        "ad_unit_fields": [
            {"key": "slot_id", "label": "Ad Placement ID", "type": "text",
             "admob_key": "ad_placement_id",
             "help": "Pangle dashboard → Ad placements (the placement ID)"},
        ],
    },
    {
        "code": "LIFTOFF",
        "name": "Liftoff_Monetize",
        "admob_source_id": "1953547073528090325",
        "admob_bidding_source_id": "4692500501762622185",
        "supports_bidding": True,
        "supports_formats": ["BANNER", "INTERSTITIAL", "NATIVE", "REWARDED",
                             "REWARDED_INTERSTITIAL", "APP_OPEN"],
        "app_fields": [
            {"key": "application_id", "label": "Application ID", "type": "text",
             "admob_key": "application_id",
             "help": "Liftoff dashboard → Apps → Application ID"},
        ],
        "ad_unit_fields": [
            {"key": "placement_reference_id", "label": "Placement Reference ID",
             "type": "text", "admob_key": "placement_reference_id",
             "help": "Liftoff dashboard → Placements"},
        ],
    },
]
NETWORK_BY_CODE = {n["code"]: n for n in NETWORK_CATALOG}


# ============================================================================
# CREDENTIAL ENCRYPTION
# ============================================================================
# Authenticated encryption at rest. Primary scheme is AES-256-GCM (256-bit
# key, 96-bit random nonce, built-in integrity tag — tampering is detected on
# decrypt). The legacy Fernet (AES-128-CBC+HMAC) path is kept ONLY to decrypt
# data written by older builds; everything new is written as AES-256-GCM.
_AES_KEY = None
_FERNET = None
_ENC_PREFIX = "g1:"  # version tag identifying an AES-256-GCM blob


def _aes_key() -> bytes:
    """32-byte (256-bit) key derived from secret_key — AES-256."""
    global _AES_KEY
    if _AES_KEY is None:
        import hashlib
        raw = (settings.secret_key or "change-me-in-env").encode("utf-8")
        _AES_KEY = hashlib.sha256(raw).digest()  # 32 bytes
    return _AES_KEY


def _get_fernet():
    # Legacy decryptor for blobs written before the AES-256-GCM migration.
    global _FERNET
    if _FERNET is None:
        import base64, hashlib
        from cryptography.fernet import Fernet
        raw = (settings.secret_key or "change-me-in-env").encode("utf-8")
        key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
        _FERNET = Fernet(key)
    return _FERNET


def encrypt_str(plaintext: str) -> str:
    """Encrypt a string with AES-256-GCM. Output: 'g1:' + base64(nonce|ct|tag)."""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ct = AESGCM(_aes_key()).encrypt(nonce, (plaintext or "").encode("utf-8"), None)
    return _ENC_PREFIX + base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_str(token: str) -> str:
    """Decrypt a value produced by encrypt_str. Transparently handles three
    legacy forms so existing data keeps working:
      - 'g1:...'   -> AES-256-GCM (current)
      - 'gAAAAA...' -> old Fernet token
      - anything else -> assumed pre-encryption plaintext, returned as-is."""
    if not token:
        return ""
    if token.startswith(_ENC_PREFIX):
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            raw = base64.urlsafe_b64decode(token[len(_ENC_PREFIX):].encode("ascii"))
            return AESGCM(_aes_key()).decrypt(raw[:12], raw[12:], None).decode("utf-8")
        except Exception:
            return ""
    if token.startswith("gAAAAA"):  # legacy Fernet
        try:
            return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
        except Exception:
            return ""
    return token  # legacy plaintext (e.g. OAuth tokens stored before encryption)


def encrypt_dict(d: dict) -> str:
    return encrypt_str(json.dumps(d or {}))


def decrypt_dict(token: str) -> dict:
    raw = decrypt_str(token)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


# ============================================================================
# DATABASE
# ============================================================================
_is_sqlite = settings.database_url.startswith("sqlite")
connect_args = {"check_same_thread": False} if _is_sqlite else {}
_engine_kwargs = {"connect_args": connect_args, "echo": False}
if not _is_sqlite:
    # For a remote Postgres/MySQL backend: test each pooled connection before
    # use and recycle stale ones, so a dropped idle connection doesn't fail the
    # next query. Completely inert for the default local SQLite database.
    _engine_kwargs["pool_pre_ping"] = True
    _engine_kwargs["pool_recycle"] = 300
else:
    # Make SQLite persistence robust: if the DB lives in a sub-directory (e.g.
    # the mounted volume at /app/data when deployed), create that directory so
    # the engine can always open/create the file there — a missing dir would
    # otherwise crash on first query and look like "the database disappeared".
    try:
        from sqlalchemy.engine import make_url
        _db_file = make_url(settings.database_url).database
        if _db_file and _db_file != ":memory:":
            _db_dir = os.path.dirname(os.path.abspath(_db_file))
            if _db_dir:
                os.makedirs(_db_dir, exist_ok=True)
    except Exception as _e:
        _log(f"  warning: could not pre-create SQLite dir ({_e})")
engine = create_engine(settings.database_url, **_engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# MODELS
# ============================================================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    google_sub = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), nullable=False)
    name = Column(String(255), default="")
    picture = Column(String(512), default="")
    admob_publisher_id = Column(String(64), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    token = relationship("OAuthToken", back_populates="user", uselist=False, cascade="all, delete-orphan")
    apps = relationship("AdMobApp", back_populates="user", cascade="all, delete-orphan")
    mediation_groups = relationship("MediationGroup", back_populates="user", cascade="all, delete-orphan")


class OAuthToken(Base):
    __tablename__ = "oauth_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, default="")
    token_uri = Column(String(255), default="https://oauth2.googleapis.com/token")
    expiry = Column(DateTime, nullable=True)
    scopes = Column(Text, default="")
    user = relationship("User", back_populates="token")


class AdMobApp(Base):
    __tablename__ = "admob_apps"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    app_id = Column(String(128), nullable=False)
    name = Column(String(255), default="")
    platform = Column(String(16), default="ANDROID")
    package_name = Column(String(255), default="")
    last_synced_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="apps")
    ad_units = relationship("AdUnit", back_populates="app", cascade="all, delete-orphan")


class AdUnit(Base):
    __tablename__ = "ad_units"
    id = Column(Integer, primary_key=True)
    app_id = Column(Integer, ForeignKey("admob_apps.id"), nullable=False)
    ad_unit_id = Column(String(128), nullable=False)
    name = Column(String(255), default="")
    ad_format = Column(String(32), default="BANNER")
    last_synced_at = Column(DateTime, default=datetime.utcnow)
    app = relationship("AdMobApp", back_populates="ad_units")


class MediationGroup(Base):
    __tablename__ = "mediation_groups"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    ad_format = Column(String(32), nullable=False)
    platform = Column(String(16), nullable=False)
    status = Column(String(16), default="DRAFT")
    country_mode = Column(String(16), default="GLOBAL")
    countries = Column(JSON, default=list)
    floor_type = Column(String(32), default="ALL_PRICES")
    target_ad_unit_id = Column(String(128), default="")
    target_ad_unit_name = Column(String(255), default="")
    base_avg_ecpm = Column(Float, default=0.0)
    report_metrics = Column(JSON, default=dict)
    admob_group_id = Column(String(64), default="")
    admob_group_name = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_push_response = Column(Text, default="")
    user = relationship("User", back_populates="mediation_groups")
    waterfall_lines = relationship("WaterfallLine", back_populates="group",
                                   cascade="all, delete-orphan",
                                   order_by="WaterfallLine.priority")


class WaterfallLine(Base):
    __tablename__ = "waterfall_lines"
    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("mediation_groups.id"), nullable=False)
    priority = Column(Integer, default=0)
    line_name = Column(String(255), default="")
    ecpm_usd = Column(Float, default=0.0)
    enabled = Column(Boolean, default=True)
    network_code = Column(String(32), default="")
    cpm_mode = Column(String(16), default="MANUAL")
    admob_line_key = Column(String(64), default="")
    group = relationship("MediationGroup", back_populates="waterfall_lines")


class NetworkCredential(Base):
    __tablename__ = "network_credentials"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    app_id = Column(Integer, ForeignKey("admob_apps.id"), nullable=False)
    network_code = Column(String(32), nullable=False)
    encrypted_fields = Column(Text, default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AdUnitMapping(Base):
    __tablename__ = "ad_unit_network_mappings"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    app_id = Column(Integer, ForeignKey("admob_apps.id"), nullable=False)
    ad_unit_id = Column(String(128), nullable=False)
    network_code = Column(String(32), nullable=False)
    encrypted_fields = Column(Text, default="")
    admob_mapping_id = Column(String(64), default="")
    admob_mapping_name = Column(String(255), default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class BiddingFormatMapping(Base):
    """Per-(app, network, ad_format) bidding mapping. Each (network, format)
    pair has ONE mapping — the user picks WHICH ad unit gets the bidding
    config (via `ad_unit_id`) and fills the network's mapping fields ONCE.
    At mediation-group push time, if the builder's "Include All Bidding
    Networks" toggle is on and the pushed source ad unit matches this
    mapping's `ad_unit_id`, the mapping becomes a real AdUnitMapping on the
    source + a LIVE bidding line on the group."""
    __tablename__ = "bidding_format_mappings_v2"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    app_id = Column(Integer, ForeignKey("admob_apps.id"), nullable=False, index=True)
    network_code = Column(String(32), nullable=False)
    ad_format = Column(String(32), nullable=False)
    ad_unit_id = Column(String(128), default="")  # the chosen ad unit
    encrypted_fields = Column(Text, default="")
    enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AdMobMediationGroupCache(Base):
    """Cached snapshot of the mediation groups that ALREADY exist in the
    user's AdMob account, pulled during Sync. This lets the Cleanup screen
    list every existing group instantly (straight from the DB) without
    re-hitting the AdMob API every time — sync once, browse fast. Scoped per
    (user, publisher) and fully refreshed on each account-scoped sync."""
    __tablename__ = "admob_mediation_group_cache"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    publisher_id = Column(String(64), default="", index=True)
    group_id = Column(String(64), nullable=False)          # mediationGroupId
    display_name = Column(String(255), default="")
    platform = Column(String(16), default="")
    ad_format = Column(String(32), default="")
    state = Column(String(16), default="")                 # ENABLED / DISABLED
    ad_unit_ids = Column(JSON, default=list)               # targeting ad unit ids
    line_count = Column(Integer, default=0)
    last_synced_at = Column(DateTime, default=datetime.utcnow)


# Ad formats that bidding can be configured for.
BIDDING_FORMATS = [
    "APP_OPEN", "BANNER", "INTERSTITIAL",
    "NATIVE", "REWARDED", "REWARDED_INTERSTITIAL",
]


# ============================================================================
# OAUTH HELPERS
# ============================================================================
def _client_config() -> dict:
    return {
        "web": {
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [settings.google_redirect_uri],
        }
    }


def build_flow(state: str | None = None) -> Flow:
    flow = Flow.from_client_config(_client_config(), scopes=settings.oauth_scopes, state=state)
    flow.redirect_uri = settings.google_redirect_uri
    return flow


def get_authorization_url() -> Tuple[str, str, str]:
    flow = build_flow()
    auth_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    return auth_url, state, flow.code_verifier or ""


def credentials_from_db(token_row) -> Credentials:
    creds = Credentials(
        token=decrypt_str(token_row.access_token) or None,
        refresh_token=decrypt_str(token_row.refresh_token) or None,
        token_uri=token_row.token_uri,
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        scopes=(token_row.scopes or "").split(",") if token_row.scopes else settings.oauth_scopes,
    )
    if token_row.expiry:
        creds.expiry = token_row.expiry
    return creds


def refresh_if_needed(creds: Credentials, force: bool = False) -> Credentials:
    """Refresh the access token when it can't be trusted.

    The default google `Credentials.expired` check only fires once the
    locally-stored expiry timestamp is in the past — so it MISSES the cases
    that produce a UNAUTHENTICATED error from AdMob:
      - `expiry is None` (never persisted): `expired` is always False, so the
        token is never refreshed and silently rots after ~1 hour.
      - the grant changed server-side (access re-granted, account removed,
        re-consented elsewhere) while the local clock still says "valid".
    We therefore refresh when forced, when the creds aren't valid, OR when we
    have no expiry to trust. Caller is responsible for handling RefreshError
    (raised when the refresh token itself was revoked)."""
    needs_refresh = force or not creds.valid or creds.expiry is None
    if needs_refresh and creds.refresh_token:
        creds.refresh(GoogleRequest())
    return creds


def persist_credentials(db: Session, user: User, creds: Credentials) -> None:
    token_row = user.token
    if token_row is None:
        token_row = OAuthToken(user_id=user.id)
        db.add(token_row)
    token_row.access_token = encrypt_str(creds.token or "")
    if creds.refresh_token:
        token_row.refresh_token = encrypt_str(creds.refresh_token)
    token_row.token_uri = creds.token_uri or "https://oauth2.googleapis.com/token"
    token_row.expiry = creds.expiry if isinstance(creds.expiry, datetime) else None
    token_row.scopes = ",".join(creds.scopes or [])
    db.commit()


# ============================================================================
# ADMOB API CLIENT
# ============================================================================
class AdMobAPIError(Exception):
    pass


def _format_http_error(e: HttpError) -> str:
    try:
        payload = json.loads(e.content.decode("utf-8"))
        err = payload.get("error", {}) or {}
        msg = err.get("message", str(e))
        status = err.get("status", "")
        parts = [f"AdMob API error: {msg}"]
        if status:
            parts.append(f"[status={status}]")
        # FAILED_PRECONDITION / INVALID_ARGUMENT errors carry the real
        # reason in error.details — surface it so we can see WHICH
        # precondition / field actually failed.
        for d in err.get("details", []) or []:
            dtype = d.get("@type", "")
            if "PreconditionFailure" in dtype:
                for v in d.get("violations", []) or []:
                    parts.append(
                        f"[precondition type={v.get('type','?')} "
                        f"subject={v.get('subject','?')} "
                        f"desc={v.get('description','?')}]"
                    )
            elif "BadRequest" in dtype:
                for v in d.get("fieldViolations", []) or []:
                    parts.append(
                        f"[field={v.get('field','?')} "
                        f"desc={v.get('description','?')}]"
                    )
            elif "ErrorInfo" in dtype:
                parts.append(
                    f"[reason={d.get('reason','?')} "
                    f"metadata={d.get('metadata',{})}]"
                )
        return " ".join(parts)
    except Exception:
        return f"AdMob API error: {e}"


def _date_parts(yyyy_mm_dd: str) -> dict:
    y, m, d = yyyy_mm_dd.split("-")
    return {"year": int(y), "month": int(m), "day": int(d)}


def _admob_today():
    """Today's date in AdMob's reporting timezone (America/Los_Angeles)."""
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo("America/Los_Angeles")).date()
    except Exception:
        return (datetime.utcnow() - timedelta(hours=8)).date()


def _today_iso() -> str:
    return _admob_today().isoformat()


def _days_ago_iso(n: int) -> str:
    return (_admob_today() - timedelta(days=n)).isoformat()


def _random_suffix(n: int = 6) -> str:
    return "".join(random.choices(string.digits, k=n))


def _build_tier_name(prefix: str, ad_unit_name: str, tier: int, ecpm: float,
                     unique: bool) -> str:
    """Build the display name for a tier ad unit (and its matching waterfall
    line). AdMob caps displayName at 80 chars."""
    suffix = f"_{_random_suffix()}" if unique else ""
    full = f"{prefix}_{ad_unit_name}_line_{tier}_waterfall_ecpm_{ecpm:.2f}{suffix}"
    full = full.replace(" ", "_")
    if len(full) <= 80:
        return full
    fixed = f"{prefix}_line_{tier}_waterfall_ecpm_{ecpm:.2f}{suffix}"
    fixed = fixed.replace(" ", "_")
    room = max(8, 80 - len(fixed) - 1)
    short_name = ad_unit_name.replace(" ", "_")[:room]
    return f"{prefix}_{short_name}_line_{tier}_waterfall_ecpm_{ecpm:.2f}{suffix}"[:80]


# google-api-python-client ships static discovery docs only for "admob" v1 and
# v1beta. The `v1alpha` surface (which exposes adMobNetworkWaterfallAdUnits —
# the resource that creates real AdMob Network Waterfall backing units) isn't
# bundled, so we fetch its discovery document over HTTP once and cache it at
# module scope.
_ADMOB_V1ALPHA_DOC: dict | None = None


def _get_admob_v1alpha_doc() -> dict:
    global _ADMOB_V1ALPHA_DOC
    if _ADMOB_V1ALPHA_DOC is None:
        resp = requests.get(
            "https://admob.googleapis.com/$discovery/rest?version=v1alpha",
            timeout=20)
        resp.raise_for_status()
        _ADMOB_V1ALPHA_DOC = resp.json()
    return _ADMOB_V1ALPHA_DOC


class AdMobClient:
    def __init__(self, db: Session, user: User):
        self.db = db
        self.user = user
        if user.token is None:
            raise RuntimeError("User has no OAuth token. Sign in again.")
        creds = credentials_from_db(user.token)
        prev_token = creds.token
        try:
            creds = refresh_if_needed(creds)
        except RefreshError as e:
            raise AdMobAPIError(
                "Your Google authorization expired or was revoked. "
                "Sign out and sign in again to reconnect AdMob."
            ) from e
        # Only write the token back to the DB when it actually changed (i.e.
        # it was refreshed) — persisting unconditionally hits the DB on every
        # request even when nothing changed.
        if creds.token != prev_token:
            persist_credentials(db, user, creds)
        self._creds = creds
        self._build_services()

    def _build_services(self) -> None:
        """(Re)build the discovery service clients from the current creds.
        Called on init and again after a forced re-auth so the new access
        token is used."""
        creds = self._creds
        self.service = build("admob", "v1", credentials=creds, cache_discovery=False)
        self.service_beta = build("admob", "v1beta", credentials=creds, cache_discovery=False)
        # v1alpha — fetched lazily; if the network fetch fails the service is
        # set to None and any caller that needs it raises a clear error.
        try:
            self.service_alpha = build_from_document(
                _get_admob_v1alpha_doc(), credentials=creds)
        except Exception as e:
            _log(f"  warning: AdMob v1alpha unavailable ({type(e).__name__}: {e})")
            self.service_alpha = None

    def _force_reauth(self) -> None:
        """Force-refresh the access token, persist it, and rebuild the service
        clients. Used when AdMob returns UNAUTHENTICATED on a token that the
        local expiry clock still considered valid (e.g. the grant changed
        server-side). Raises RefreshError if the refresh token was revoked."""
        self._creds = refresh_if_needed(self._creds, force=True)
        persist_credentials(self.db, self.user, self._creds)
        self._build_services()

    def list_accounts(self) -> list[dict]:
        return self._with_quota_retry(
            lambda: self.service.accounts().list().execute()
        ).get("account", [])

    def get_publisher_id(self) -> str:
        """Resolve the publisher ID this token is actually authorized for.

        The cached `user.admob_publisher_id` (seeded from .env or a prior
        sign-in) is NOT trusted blindly: AdMob returns a misleading
        `401 UNAUTHENTICATED / "missing required authentication credential"`
        — NOT 403 — when you query a publisher the token doesn't own. So if
        the user switched AdMob accounts, the stale cached ID makes every call
        look like an auth failure. We therefore verify the cached ID against
        the accounts this token can actually access, and switch to the real
        one if it isn't in the list. Verified once per client instance."""
        if getattr(self, "_publisher_id", None):
            return self._publisher_id
        cached = (self.user.admob_publisher_id or "").strip()
        accounts = self.list_accounts()
        if not accounts:
            raise AdMobAPIError(
                "No AdMob account found for this Google user. "
                "Sign in with the Google account that owns the AdMob publisher."
            )
        accessible = [a.get("publisherId", "") for a in accounts if a.get("publisherId")]
        if cached and cached in accessible:
            pub_id = cached
        else:
            pub_id = accessible[0]
            if cached and cached != pub_id:
                _log(f"  cached publisher {cached} is not accessible by this "
                     f"Google account; switching to {pub_id}")
            self.user.admob_publisher_id = pub_id
            self.db.commit()
        self._publisher_id = pub_id
        return pub_id

    def list_apps(self) -> list[dict]:
        parent = f"accounts/{self.get_publisher_id()}"
        return self._with_quota_retry(
            lambda: self.service.accounts().apps().list(parent=parent).execute()
        ).get("apps", [])

    def list_ad_units(self) -> list[dict]:
        parent = f"accounts/{self.get_publisher_id()}"
        return self._with_quota_retry(
            lambda: self.service.accounts().adUnits().list(parent=parent).execute()
        ).get("adUnits", [])

    def fetch_network_report_for_ad_units(self, ad_unit_ids: list[str],
                                          start: str, end: str,
                                          countries: list[str] | None = None,
                                          report_type: str = "mediation") -> dict[str, dict]:
        # report_type:
        #   "mediation" (default) -> Mediation report, eCPM = OBSERVED_ECPM.
        #       Matches the value shown in the AdMob UI (whole waterfall, all
        #       ad sources). Best for seeing real per-ad-unit performance.
        #   "network" -> Network report, eCPM = AdMob Network earnings/impr.
        #       Only the AdMob Network ad source. Useful when building the
        #       AdMob Network waterfall tiers specifically.
        if not ad_unit_ids:
            return {}
        use_mediation = (report_type or "mediation").lower() != "network"
        parent = f"accounts/{self.get_publisher_id()}"
        dimension_filters = [
            {"dimension": "AD_UNIT", "matchesAny": {"values": ad_unit_ids}}
        ]
        # Country-scoped metrics. When specific countries are requested we add a
        # COUNTRY dimension filter so eCPM / revenue / requests reflect THAT geo
        # instead of the global all-countries aggregate. Without this filter the
        # report returns identical totals for every country selected in the UI.
        # COUNTRY values are ISO 3166-1 alpha-2 codes (US, IN, SA, BR, ...).
        cc = [c.strip().upper() for c in (countries or []) if c and c.strip()]
        if cc:
            dimension_filters.append(
                {"dimension": "COUNTRY", "matchesAny": {"values": cc}}
            )
        if use_mediation:
            # Mediation report -> OBSERVED_ECPM matches the AdMob UI exactly.
            metrics = ["AD_REQUESTS", "MATCHED_REQUESTS", "IMPRESSIONS",
                       "ESTIMATED_EARNINGS", "CLICKS", "IMPRESSION_CTR",
                       "MATCH_RATE", "OBSERVED_ECPM"]
        else:
            # Network report -> AdMob Network only; eCPM derived from earnings.
            metrics = ["AD_REQUESTS", "MATCHED_REQUESTS", "IMPRESSIONS",
                       "ESTIMATED_EARNINGS", "CLICKS", "IMPRESSION_CTR",
                       "IMPRESSION_RPM", "MATCH_RATE", "SHOW_RATE"]
        body = {
            "reportSpec": {
                "dateRange": {"startDate": _date_parts(start), "endDate": _date_parts(end)},
                "dimensions": ["AD_UNIT"],
                "dimensionFilters": dimension_filters,
                "metrics": metrics,
                # CRITICAL: force USD. Without this the AdMob reporting API
                # returns money (ESTIMATED_EARNINGS, OBSERVED_ECPM) in the
                # ACCOUNT's local currency (e.g. AED), which the code then
                # reads as if it were USD — inflating every eCPM/revenue by the
                # FX rate (AED = 3.6725, so ~3.67x too high). Requesting USD
                # makes the numbers match the AdMob UI exactly.
                "localizationSettings": {"currencyCode": "USD"},
            }
        }
        report_res = (self.service.accounts().mediationReport()
                      if use_mediation else self.service.accounts().networkReport())
        resp = self._with_quota_retry(
            lambda: report_res.generate(parent=parent, body=body).execute()
        )

        rows = resp if isinstance(resp, list) else []
        out: dict[str, dict] = {}
        for entry in rows:
            row = entry.get("row")
            if not row:
                continue
            dims = row.get("dimensionValues", {})
            metrics = row.get("metricValues", {})
            ad_unit = dims.get("AD_UNIT", {}).get("value", "")
            if not ad_unit:
                continue

            def _int(key: str) -> int:
                v = metrics.get(key, {}).get("integerValue")
                return int(v) if v is not None else 0

            def _double(key: str) -> float:
                v = metrics.get(key, {}).get("doubleValue")
                if v is not None:
                    return float(v)
                iv = metrics.get(key, {}).get("integerValue")
                return float(iv) if iv is not None else 0.0

            def _micros(key: str) -> int:
                v = metrics.get(key, {}).get("microsValue")
                if v is not None:
                    return int(v)
                iv = metrics.get(key, {}).get("integerValue")
                if iv is not None:
                    return int(iv)
                dv = metrics.get(key, {}).get("doubleValue")
                return int(float(dv) * 1_000_000) if dv is not None else 0

            ad_requests = _int("AD_REQUESTS")
            matched = _int("MATCHED_REQUESTS")
            impressions = _int("IMPRESSIONS")
            clicks = _int("CLICKS")
            earnings_micros = _micros("ESTIMATED_EARNINGS")
            revenue_usd = earnings_micros / 1_000_000.0
            if use_mediation:
                # eCPM straight from AdMob's OBSERVED_ECPM (matches the UI).
                ecpm_usd = _micros("OBSERVED_ECPM") / 1_000_000.0
                rpm_usd = (revenue_usd / impressions * 1000.0) if impressions else 0.0
            else:
                # Network report: derive eCPM from earnings / impressions.
                rpm_usd = _micros("IMPRESSION_RPM") / 1_000_000.0
                ecpm_usd = (revenue_usd / impressions * 1000.0) if impressions else 0.0

            match_rate = (matched / ad_requests) if ad_requests else 0.0
            show_rate = (impressions / matched) if matched else 0.0
            fill_rate = (impressions / ad_requests) if ad_requests else 0.0
            ctr = _double("IMPRESSION_CTR")

            out[ad_unit] = {
                "ad_requests": ad_requests, "matched_requests": matched,
                "impressions": impressions, "clicks": clicks,
                "revenue_usd": round(revenue_usd, 2), "ecpm_usd": round(ecpm_usd, 2),
                "rpm_usd": round(rpm_usd, 2), "match_rate": round(match_rate, 4),
                "show_rate": round(show_rate, 4), "fill_rate": round(fill_rate, 4),
                "ctr": round(ctr, 4),
            }
        return out

    def list_ad_sources(self) -> list[dict]:
        if hasattr(self, "_ad_sources_cache"):
            return self._ad_sources_cache
        parent = f"accounts/{self.get_publisher_id()}"
        resp = self._with_quota_retry(
            lambda: self.service_alpha.accounts().adSources().list(parent=parent).execute()
        )
        self._ad_sources_cache = resp.get("adSources", []) or []
        return self._ad_sources_cache

    def list_adapters_for_source(self, ad_source_id: str) -> list[dict]:
        cache_key = f"_adapters_cache_{ad_source_id}"
        if hasattr(self, cache_key):
            return getattr(self, cache_key)
        parent = f"accounts/{self.get_publisher_id()}/adSources/{ad_source_id}"
        resp = self._with_quota_retry(
            lambda: self.service_alpha.accounts().adSources().adapters().list(parent=parent).execute()
        )
        out = resp.get("adapters", []) or []
        setattr(self, cache_key, out)
        return out

    def find_source_id_for_network(self, network_code: str) -> str:
        """Resolve the WATERFALL (non-bidding) ad source id for a network."""
        cat = NETWORK_BY_CODE.get(network_code.upper())
        if not cat:
            return ""
        return cat.get("admob_source_id") or ""

    def find_bidding_source_id_for_network(self, network_code: str) -> str:
        """Resolve the BIDDING ad source id for a network. AdMob exposes a
        separate "(bidding)" source per network (e.g. Mintegral=
        1357746574408896200 vs Mintegral (bidding)=6250601289653372374).
        Bidding LIVE lines AND their AdUnitMappings MUST use the bidding
        source; using the waterfall source triggers "CPM mode unsupported"
        or adapter-mismatch errors."""
        cat = NETWORK_BY_CODE.get(network_code.upper())
        if not cat:
            return ""
        return cat.get("admob_bidding_source_id") or cat.get("admob_source_id") or ""

    # Two distinct AdMob ad sources — DO NOT confuse them:
    #  - "AdMob Network"           -> LIVE bidding line. Only 1 per group.
    #  - "AdMob Network Waterfall" -> MANUAL waterfall lines. MANY per group.
    # Using "AdMob Network" for manual lines triggers AdMob's
    # "Max allowed AdMob Network lines exceeded" error.
    ADMOB_NETWORK_SOURCE_ID = "5450213213286189855"
    ADMOB_WATERFALL_SOURCE_ID = "1215381445328257950"

    def get_admob_network_source_id(self) -> str:
        """The 'AdMob Network' ad source — for the LIVE bidding line."""
        try:
            for src in self.list_ad_sources():
                if (src.get("title") or "").strip().lower() == "admob network":
                    return src.get("adSourceId") or self.ADMOB_NETWORK_SOURCE_ID
        except AdMobAPIError:
            pass
        return self.ADMOB_NETWORK_SOURCE_ID

    def get_admob_waterfall_source_id(self) -> str:
        """The 'AdMob Network Waterfall' ad source — for MANUAL waterfall
        lines. This source allows many manual lines in a single group."""
        try:
            for src in self.list_ad_sources():
                t = (src.get("title") or "").strip().lower()
                if t == "admob network waterfall":
                    return src.get("adSourceId") or self.ADMOB_WATERFALL_SOURCE_ID
        except AdMobAPIError:
            pass
        return self.ADMOB_WATERFALL_SOURCE_ID

    def get_admob_waterfall_adapter(self, ad_format: str, platform: str) -> dict:
        """Find the 'AdMob Network Waterfall' adapter for a given format +
        platform. Each adapter has exactly one required config field
        ('Ad Unit ID') whose value must be the tier ad unit's full ID.

        AdMob adapter `formats` use APP_OPEN (not APP_OPEN_AD) and may use
        BANNER_AND_INTERSTITIAL; we normalise accordingly.
        """
        source_id = self.get_admob_waterfall_source_id()
        adapters = self.list_adapters_for_source(source_id)
        fmt = (ad_format or "").upper()
        if fmt == "APP_OPEN_AD":
            fmt = "APP_OPEN"
        plat = (platform or "").upper()

        def fmt_match(a: dict) -> bool:
            adf = [f.upper() for f in (a.get("formats") or [])]
            if fmt in adf:
                return True
            # BANNER / INTERSTITIAL adapters are bundled as
            # BANNER_AND_INTERSTITIAL on the waterfall source.
            if fmt in ("BANNER", "INTERSTITIAL") and "BANNER_AND_INTERSTITIAL" in adf:
                return True
            return False

        for a in adapters:
            if (a.get("platform") or "").upper() == plat and fmt_match(a):
                return a
        # fallback: any adapter on the right platform
        for a in adapters:
            if (a.get("platform") or "").upper() == plat:
                return a
        if adapters:
            return adapters[0]
        raise AdMobAPIError(
            "No 'AdMob Network Waterfall' adapter found for "
            f"format={ad_format} platform={platform}"
        )

    def create_waterfall_mapping_on_source(
        self,
        source_ad_unit_id: str,
        tier_ad_unit_id: str,
        ad_format: str,
        platform: str,
        display_name: str = "",
    ) -> str:
        """Create an AdUnitMapping ON the source ad unit that routes a
        waterfall line to the given TIER ad unit, via the 'AdMob Network
        Waterfall' adapter.

        The adapter's single required config ('Ad Unit ID') is set to the
        tier ad unit's full id. Returns the created mapping's resource name
        (accounts/{pub}/adUnits/{src}/adUnitMappings/{id}) for use in a
        mediation group line's adUnitMappings dict.
        """
        adapter = self.get_admob_waterfall_adapter(ad_format, platform)
        adapter_id = str(adapter.get("adapterId", ""))
        meta = adapter.get("adapterConfigMetadata", []) or []
        if not meta:
            raise AdMobAPIError(
                f"Waterfall adapter {adapter_id} has no config metadata."
            )
        config_id = str(meta[0].get("adapterConfigMetadataId", ""))

        short_src = source_ad_unit_id.split("/")[-1]
        parent = f"accounts/{self.get_publisher_id()}/adUnits/{short_src}"
        body = {
            "adapterId": adapter_id,
            "adUnitConfigurations": {config_id: tier_ad_unit_id},
            "state": "ENABLED",
        }
        if display_name:
            body["displayName"] = display_name[:80]
        try:
            resp = self._with_quota_retry(
                lambda: self.service_alpha.accounts().adUnits()
                .adUnitMappings().create(parent=parent, body=body).execute()
            )
        except HttpError as e:
            raise AdMobAPIError(_format_http_error(e)) from e
        return resp.get("name", "") or ""

    def get_mediation_group_in_admob(self, mediation_group_id: str) -> dict:
        """Read a single mediation group's current state by ID.

        NOTE: The AdMob v1beta `mediationGroups` resource only exposes
        `list`, `create`, `patch`, and `delete` — there is no `get` method.
        Calling `.get(...)` on the Resource raises
        `AttributeError: 'Resource' object has no attribute 'get'`.
        We emulate get by listing and filtering client-side.
        """
        parent = f"accounts/{self.get_publisher_id()}"
        full_name = f"{parent}/mediationGroups/{mediation_group_id}"
        target_id = str(mediation_group_id).strip()
        page_token: str | None = None
        while True:
            kwargs = {"parent": parent, "pageSize": 200}
            if page_token:
                kwargs["pageToken"] = page_token
            resp = self._with_quota_retry(
                lambda kw=kwargs: self.service_alpha.accounts()
                .mediationGroups().list(**kw).execute()
            )
            for g in resp.get("mediationGroups", []) or []:
                gid = str(g.get("mediationGroupId") or "").strip()
                gname = str(g.get("name") or "")
                if gid == target_id or gname == full_name \
                        or gname.endswith(f"/{target_id}"):
                    return g
            page_token = resp.get("nextPageToken") or None
            if not page_token:
                break
        raise AdMobAPIError(
            f"Mediation group {mediation_group_id} not found under {parent}."
        )

    # ========================================================================
    # Quota / rate-limit retry helper
    # ========================================================================
    def _with_quota_retry(self, fn, max_retries: int = 2, base_delay: float = 3.0):
        """Execute fn(); transparently recover from two classes of error:

        1. UNAUTHENTICATED / 401 — the access token went stale even though the
           local expiry clock still considered it valid (this happens when the
           AdMob grant changes server-side). We force a token refresh ONCE,
           rebuild the service clients, and retry. If the refresh token itself
           was revoked, we surface a clean "sign in again" message instead of
           a cryptic 502.
        2. RESOURCE_EXHAUSTED / quota / 429 — retry with a SHORT backoff
           (3s, 6s ≈ 9s total) and then give up. We deliberately fail fast: if
           the quota window is genuinely empty (e.g. daily cap exceeded from
           prior test runs), waiting 2+ minutes per call doesn't help — the
           only fix is to wait minutes/hours or request a quota increase in
           Google Cloud Console.

        Sometimes a 60-second sleep helps; usually it doesn't. If you do
        want longer retries on a specific call, bump max_retries at the
        call site rather than globally."""
        last_err: HttpError | None = None
        auth_retried = False
        attempt = 0
        while attempt < max_retries:
            try:
                return fn()
            except HttpError as e:
                content_lower = ""
                try:
                    content_lower = (e.content or b"").decode("utf-8", errors="ignore").lower()
                except Exception:
                    pass
                full = f"{str(e).lower()} {content_lower}"
                status = getattr(getattr(e, "resp", None), "status", None)

                # --- auth recovery (force-refresh + retry, once) ---
                is_auth = (
                    status == 401
                    or "unauthenticated" in full
                    or "missing required authentication" in full
                    or "invalid authentication credential" in full
                    or "invalid_grant" in full
                )
                if is_auth and not auth_retried:
                    auth_retried = True
                    _log("     ⚠ AdMob auth error; forcing token refresh and retrying")
                    try:
                        self._force_reauth()
                    except RefreshError as re:
                        raise AdMobAPIError(
                            "Your Google authorization expired or was revoked. "
                            "Sign out and sign in again to reconnect AdMob."
                        ) from re
                    continue  # retry without consuming a quota attempt

                # --- quota / rate-limit recovery ---
                is_quota = any(kw in full for kw in (
                    "exhausted", "resource_exhausted", "quota",
                    "rate limit", "ratelimit", "429",
                ))
                if is_quota and attempt < max_retries - 1:
                    wait = base_delay * (2 ** attempt)
                    _log(f"     ⚠ AdMob quota hit; "
                         f"sleeping {wait:.0f}s before retry "
                         f"(attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait)
                    last_err = e
                    attempt += 1
                    continue
                raise AdMobAPIError(_format_http_error(e)) from e
        if last_err is not None:
            raise AdMobAPIError(_format_http_error(last_err))
        raise AdMobAPIError("Quota retries exhausted")

    # ========================================================================
    # AD UNIT MAPPING helpers (third-party bidding network configs)
    # ========================================================================
    def list_ad_unit_mappings(self, ad_unit_id: str) -> list[dict]:
        """List existing AdUnitMappings (third-party network configs) for
        a given ad unit. Accepts either 'ca-app-pub-X/Y' or the short Y form.
        """
        short_id = ad_unit_id.split("/")[-1] if "/" in ad_unit_id else ad_unit_id
        parent = f"accounts/{self.get_publisher_id()}/adUnits/{short_id}"
        resp = self._with_quota_retry(
            lambda: self.service_alpha.accounts().adUnits().adUnitMappings().list(
                parent=parent,
            ).execute()
        )
        return resp.get("adUnitMappings", []) or []

    def get_adapter_to_source_map(self) -> dict[str, str]:
        """Build and cache {adapter_id: ad_source_id} for every adapter under
        every ad source."""
        if hasattr(self, "_adapter_source_map"):
            return self._adapter_source_map
        mapping: dict[str, str] = {}
        try:
            for src in self.list_ad_sources():
                src_id = src.get("adSourceId", "")
                if not src_id:
                    continue
                try:
                    for ad in self.list_adapters_for_source(src_id):
                        adapter_id = str(ad.get("adapterId", ""))
                        if adapter_id:
                            mapping[adapter_id] = src_id
                except AdMobAPIError:
                    continue
        except AdMobAPIError:
            pass
        self._adapter_source_map = mapping
        return mapping

    # ========================================================================
    # v1alpha — AdMob Network Waterfall ad units (the real backing units that
    # the old internal-cURL hack tried to fake). These ARE creatable via the
    # public v1alpha API; the earlier "HARD LIMIT — UI only" conclusion was
    # based on v1beta, which doesn't expose this resource.
    # ========================================================================
    def list_waterfall_ad_units(self, page_size: int = 1000) -> list[dict]:
        """List all AdMob Network Waterfall backing ad units (v1alpha)."""
        if self.service_alpha is None:
            raise AdMobAPIError(
                "AdMob v1alpha service not available — discovery doc "
                "fetch failed at startup")
        units: list[dict] = []
        page = None
        while True:
            kw = {"parent": f"accounts/{self.get_publisher_id()}",
                  "pageSize": page_size}
            if page:
                kw["pageToken"] = page
            try:
                r = (self.service_alpha.accounts()
                     .adMobNetworkWaterfallAdUnits().list(**kw).execute())
            except HttpError as e:
                raise AdMobAPIError(_format_http_error(e)) from e
            units.extend(r.get("adMobNetworkWaterfallAdUnits", []) or [])
            page = r.get("nextPageToken")
            if not page:
                break
        return units

    def batch_create_waterfall_ad_units(self, *, app_id: str,
                                         primary_ad_unit_id: str,
                                         ad_format: str,
                                         tiers: list[tuple]) -> list[dict]:
        """Batch-create AdMob Network Waterfall backing units (v1alpha) —
        the public-API replacement for the old internal-cURL hack.

        Args:
          app_id: full app id, e.g. "ca-app-pub-XXX~YYYY".
          primary_ad_unit_id: full ad unit id, e.g. "ca-app-pub-XXX/YYY" —
            AdMob auto-creates an AdUnitMapping from this primary ad unit to
            each created backing unit (returned in
            mappingSetting.adUnitMappingId).
          ad_format: BANNER / INTERSTITIAL / NATIVE / REWARDED /
            REWARDED_INTERSTITIAL / APP_OPEN.
          tiers: [(display_name, ecpm_usd), ...] — one entry per backing unit.

        Returns the created `adMobNetworkWaterfallAdUnits` list — each item
        carries `name`, `admobNetworkWaterfallAdUnitId` (the "pubid"), and
        `mappingSetting.adUnitMappingId` (the auto-created mapping)."""
        if self.service_alpha is None:
            raise AdMobAPIError(
                "AdMob v1alpha service not available — discovery doc "
                "fetch failed at startup")
        fmt = (ad_format or "").upper()
        # RICH_MEDIA is rejected for REWARDED / REWARDED_INTERSTITIAL per the
        # v1alpha schema; for everything else both media types are allowed.
        ad_types = (["VIDEO"]
                    if fmt in ("REWARDED", "REWARDED_INTERSTITIAL")
                    else ["RICH_MEDIA", "VIDEO"])
        body = {"requests": [{
            "adMobNetworkWaterfallAdUnit": {
                "appId": app_id,
                "displayName": (name or "")[:80],
                "format": fmt,
                "adTypes": ad_types,
                "cpmFloorSettings": {
                    "globalFloorMicros":
                        str(int(round(float(ecpm) * 1_000_000)))
                },
                "mappingSetting": {"primaryAdUnitId": primary_ad_unit_id},
            }
        } for (name, ecpm) in tiers]}
        try:
            r = (self.service_alpha.accounts()
                 .adMobNetworkWaterfallAdUnits().batchCreate(
                     parent=f"accounts/{self.get_publisher_id()}",
                     body=body).execute())
        except HttpError as e:
            raise AdMobAPIError(_format_http_error(e)) from e
        return r.get("adMobNetworkWaterfallAdUnits", []) or []

    def batch_create_waterfall_ad_units_multi(
        self, reqs: list[dict], chunk: int = 50,
    ) -> tuple[dict[str, list[dict]], set]:
        """Create the tier backing units for MANY source ad units in a few
        batchCreate calls instead of one call per group. Cuts a 12-group push
        from 12 batchCreate round-trips to ~2-3 (the AdMob write latency +
        quota backoff per call is what makes big pushes slow).

        reqs: [{app_id, primary_ad_unit_id, ad_format,
                tiers: [(display_name, ecpm), ...]}, ...]
        Returns ({primary_ad_unit_id: [unit, ...] in tier order},
                 failed_primaries) — callers fall back to the per-group call
        for any primary in failed_primaries, so a failed chunk never kills
        the whole push and never double-creates units from healthy chunks.
        """
        if self.service_alpha is None:
            raise AdMobAPIError(
                "AdMob v1alpha service not available — discovery doc "
                "fetch failed at startup")
        flat: list[dict] = []
        meta: list[str] = []          # parallel: primary ad unit per request
        for r in reqs:
            fmt = (r["ad_format"] or "").upper()
            ad_types = (["VIDEO"]
                        if fmt in ("REWARDED", "REWARDED_INTERSTITIAL")
                        else ["RICH_MEDIA", "VIDEO"])
            for (name, ecpm) in r["tiers"]:
                flat.append({"adMobNetworkWaterfallAdUnit": {
                    "appId": r["app_id"],
                    "displayName": (name or "")[:80],
                    "format": fmt,
                    "adTypes": ad_types,
                    "cpmFloorSettings": {
                        "globalFloorMicros":
                            str(int(round(float(ecpm) * 1_000_000)))
                    },
                    "mappingSetting": {
                        "primaryAdUnitId": r["primary_ad_unit_id"]},
                }})
                meta.append(r["primary_ad_unit_id"])
        out: dict[str, list[dict]] = {}
        failed: set = set()
        parent = f"accounts/{self.get_publisher_id()}"
        for i in range(0, len(flat), chunk):
            c_reqs = flat[i:i + chunk]
            c_meta = meta[i:i + chunk]
            try:
                resp = self._with_quota_retry(
                    lambda c=c_reqs: self.service_alpha.accounts()
                    .adMobNetworkWaterfallAdUnits().batchCreate(
                        parent=parent, body={"requests": c}).execute()
                )
                units = resp.get("adMobNetworkWaterfallAdUnits", []) or []
                if len(units) != len(c_reqs):
                    raise AdMobAPIError(
                        f"batchCreate returned {len(units)} units for "
                        f"{len(c_reqs)} requests — order can't be trusted")
                for prim, u in zip(c_meta, units):
                    out.setdefault(prim, []).append(u)
            except AdMobAPIError as e:
                _log(f"  multi-batchCreate chunk failed "
                     f"({len(c_reqs)} reqs): {e} — those groups will use "
                     f"the per-group call instead")
                failed.update(c_meta)
        # A primary with any failed chunk must be fully per-group re-created.
        for prim in failed:
            out.pop(prim, None)
        return out, failed

    def batch_create_bidding_mappings(
        self, reqs: list[dict], chunk: int = 50,
    ) -> dict[tuple, str]:
        """Create MANY bidding AdUnitMappings in a few batchCreate calls
        (instead of one create per source ad unit per network).

        reqs: [{ad_unit_id, network_code, adapter_id, configs, display_name}]
        Returns {(ad_unit_id, network_code): mapping_resource_name}. Pairs
        from a failed chunk are simply absent — the caller falls back to the
        old per-item create for them.
        """
        if self.service_alpha is None:
            raise AdMobAPIError(
                "AdMob v1alpha service not available — discovery doc "
                "fetch failed at startup")
        pub = self.get_publisher_id()
        flat: list[dict] = []
        meta: list[tuple] = []
        for r in reqs:
            short = (r["ad_unit_id"].split("/")[-1]
                     if "/" in r["ad_unit_id"] else r["ad_unit_id"])
            flat.append({
                "parent": f"accounts/{pub}/adUnits/{short}",
                "adUnitMapping": {
                    "displayName": (r["display_name"] or "")[:80],
                    "adapterId": r["adapter_id"],
                    "adUnitConfigurations": r["configs"],
                    "state": "ENABLED",
                },
            })
            meta.append((r["ad_unit_id"], r["network_code"]))
        out: dict[tuple, str] = {}
        for i in range(0, len(flat), chunk):
            c_reqs = flat[i:i + chunk]
            c_meta = meta[i:i + chunk]
            try:
                resp = self._with_quota_retry(
                    lambda c=c_reqs: self.service_alpha.accounts()
                    .adUnitMappings().batchCreate(
                        parent=f"accounts/{pub}",
                        body={"requests": c}).execute()
                )
                mps = resp.get("adUnitMappings", []) or []
                if len(mps) != len(c_reqs):
                    raise AdMobAPIError(
                        f"batchCreate returned {len(mps)} mappings for "
                        f"{len(c_reqs)} requests")
                for key, mp in zip(c_meta, mps):
                    name = mp.get("name", "") or ""
                    if name:
                        out[key] = name
            except AdMobAPIError as e:
                _log(f"  bidding multi-batchCreate chunk failed "
                     f"({len(c_reqs)} reqs): {e} — those mappings will be "
                     f"created per-item instead")
        return out

    # ========================================================================
    # NEW (FIX): replicate source ad unit's bidding mappings to tier ad units
    # ========================================================================
    def replicate_source_mappings_to_tier_ad_units(
        self,
        source_ad_unit_id: str,
        tier_ad_unit_ids: list[str],
    ) -> tuple[dict[str, dict[str, str]], list[dict], list[str]]:
        """For each tier ad unit, recreate every third-party (non-AdMob)
        AdUnitMapping that the source ad unit has, using the same adapterId
        and adUnitConfigurations.

        This is the LINE-BY-LINE MAPPING that was missing. Without it, when
        the mediation group targets tier ad units alongside the source,
        the bidding LIVE lines have no place to ask for a bid for those
        tiers — so they go unfilled.

        Returns:
            (per_ad_unit_mappings, errors, network_titles)
            per_ad_unit_mappings: {ad_unit_id: {ad_source_id: mapping_name}}
                keyed by EVERY ad unit (source + each tier).
            errors: list of dicts for any replication that failed.
            network_titles: list of unique network titles successfully mapped.
        """
        out: dict[str, dict[str, str]] = {source_ad_unit_id: {}}
        for tid in tier_ad_unit_ids:
            if tid:
                out[tid] = {}
        errors: list[dict] = []
        network_titles: list[str] = []

        # 1. Read source's existing mappings
        try:
            source_mappings = self.list_ad_unit_mappings(source_ad_unit_id)
        except AdMobAPIError as e:
            errors.append({"tier_ad_unit_id": "", "ad_source_id": "",
                           "stage": "list_source_mappings", "error": str(e)})
            return out, errors, network_titles

        adapter_to_source = self.get_adapter_to_source_map()
        admob_source_id = self.get_admob_network_source_id()

        # 2. Source titles for nicer error messages
        source_titles: dict[str, str] = {}
        try:
            for src in self.list_ad_sources():
                sid = src.get("adSourceId", "")
                if sid:
                    source_titles[sid] = src.get("title", "") or sid
        except AdMobAPIError:
            pass

        # 3. Capture each non-AdMob mapping as a replication template
        # ad_source_id -> {adapter_id, configs, source_mapping_name, title}
        templates: dict[str, dict] = {}
        for m in source_mappings:
            adapter_id = str(m.get("adapterId", ""))
            configs = m.get("adUnitConfigurations", {}) or {}
            mapping_name = m.get("name", "")
            state = (m.get("state") or "").upper()
            src_id = adapter_to_source.get(adapter_id, "")

            if not src_id or not mapping_name:
                continue
            if src_id == admob_source_id:
                continue  # AdMob Network handled separately
            if state and state != "ENABLED":
                errors.append({"tier_ad_unit_id": "", "ad_source_id": src_id,
                               "stage": "source_mapping_disabled",
                               "error": f"source mapping for "
                                        f"{source_titles.get(src_id, src_id)} "
                                        f"is in state {state!r}; not replicating"})
                continue
            if not configs:
                errors.append({"tier_ad_unit_id": "", "ad_source_id": src_id,
                               "stage": "source_mapping_empty_config",
                               "error": f"source mapping for "
                                        f"{source_titles.get(src_id, src_id)} "
                                        f"has empty adUnitConfigurations; "
                                        f"cannot replicate"})
                continue

            # Record the source's own mapping
            out[source_ad_unit_id][src_id] = mapping_name
            templates[src_id] = {
                "adapter_id": adapter_id,
                "configs": configs,
                "title": source_titles.get(src_id, src_id),
            }
            network_titles.append(source_titles.get(src_id, src_id))

        if not templates:
            # No third-party bidding to replicate; bidding section will be empty.
            # AdMob Network LIVE line will be the only bidding line (auto-added).
            return out, errors, network_titles

        # 4. Create ALL tier mappings in ONE batched call (chunked) instead of
        #    one API call + a 1-second sleep per (tier x network). The old loop
        #    cost ~1s per mapping — minutes for many tiers/networks/ad units.
        #    adUnitMappings.batchCreate does the whole set in a single request,
        #    so the push is dramatically faster and uses far less write quota.
        pub_id = self.get_publisher_id()
        short_to_tier: dict[str, str] = {}   # ad-unit short id -> full tier id
        batch_requests: list[dict] = []
        for tier_id in tier_ad_unit_ids:
            if not tier_id:
                continue
            short = tier_id.split("/")[-1] if "/" in tier_id else tier_id
            short_to_tier[short] = tier_id
            parent = f"accounts/{pub_id}/adUnits/{short}"
            for src_id, tmpl in templates.items():
                # `name` is output-only; labels go in `displayName`.
                batch_requests.append({
                    "parent": parent,
                    "adUnitMapping": {
                        "displayName": (f"tier_{src_id[:8]}_{short[-6:]}_"
                                        f"{_random_suffix(4)}")[:80],
                        "adapterId": tmpl["adapter_id"],
                        "adUnitConfigurations": tmpl["configs"],
                        "state": "ENABLED",
                    },
                })

        CHUNK = 50
        for i in range(0, len(batch_requests), CHUNK):
            chunk = batch_requests[i:i + CHUNK]
            try:
                resp = self._with_quota_retry(
                    lambda c=chunk: self.service_alpha.accounts()
                    .adUnitMappings().batchCreate(
                        parent=f"accounts/{pub_id}",
                        body={"requests": c},
                    ).execute()
                )
            except AdMobAPIError as e:
                errors.append({"tier_ad_unit_id": "", "ad_source_id": "",
                               "stage": "batch_create_tier_mappings",
                               "error": str(e)})
                continue
            # Map every created mapping back to (tier_id, src_id) via its
            # resource name (.../adUnits/<short>/...) and adapterId.
            for mp in resp.get("adUnitMappings", []) or []:
                name = mp.get("name", "") or ""
                src_id = adapter_to_source.get(str(mp.get("adapterId", "")), "")
                short = ""
                if "/adUnits/" in name:
                    short = name.split("/adUnits/", 1)[1].split("/", 1)[0]
                tier_id = short_to_tier.get(short, "")
                if tier_id and src_id and name:
                    out[tier_id][src_id] = name

        # De-dupe network titles
        network_titles = list(dict.fromkeys(network_titles))
        return out, errors, network_titles

    # ========================================================================
    # NEW (FIX): build LIVE bidding lines from the per-ad-unit mapping dict
    # ========================================================================
    def build_bidding_lines_from_mappings(
        self,
        per_ad_unit_mappings: dict[str, dict[str, str]],
    ) -> tuple[list[dict], list[str]]:
        """Build LIVE bidding lines from {ad_unit_id: {ad_source_id: mapping_name}}.

        For each non-AdMob ad source present in any ad unit's mapping, emit
        one LIVE line whose adUnitMappings dict covers every ad unit that
        has a mapping for that source. AdMob Network is excluded here and
        added explicitly by the caller.

        Returns (lines, source_titles_added).
        """
        admob_source_id = self.get_admob_network_source_id()

        # ad_source_id -> {ad_unit_id: mapping_name}
        by_source: dict[str, dict[str, str]] = {}
        for ad_unit_id, src_to_name in per_ad_unit_mappings.items():
            for src_id, mapping_name in src_to_name.items():
                if src_id == admob_source_id or not mapping_name:
                    continue
                by_source.setdefault(src_id, {})[ad_unit_id] = mapping_name

        source_titles: dict[str, str] = {}
        try:
            for src in self.list_ad_sources():
                sid = src.get("adSourceId", "")
                if sid:
                    source_titles[sid] = src.get("title", "") or sid
        except AdMobAPIError:
            pass

        lines: list[dict] = []
        titles_added: list[str] = []
        for src_id, ad_unit_mappings in by_source.items():
            if not ad_unit_mappings:
                continue
            title = source_titles.get(src_id) or f"Source {src_id[:12]}"
            lines.append({
                "adSourceId": src_id,
                "displayName": f"{title} (bidding)"[:80],
                "cpmMode": "LIVE",
                "state": "ENABLED",
                "adUnitMappings": ad_unit_mappings,
            })
            titles_added.append(title)
        return lines, titles_added

    # ========================================================================
    # NEW (FIX): audit group state after creation (issue 1)
    # ========================================================================
    # ========================================================================
    # CREATE AD UNIT (tier creation)
    # ========================================================================
    def create_ad_unit_in_admob(
        self,
        app_id_full: str,
        display_name: str,
        ad_format: str,
    ) -> dict:
        """POST /v1beta/accounts/{pub}/adUnits — create a new AdMob ad unit.

        NOTE: The AdMob v1beta `AdUnit` resource has NO `state` field. The
        valid fields are: name (output), adUnitId (output), appId,
        displayName, adFormat, adTypes, rewardSettings. Sending `state`
        triggers: "Invalid JSON payload received. Unknown name 'state' at
        'ad_unit': Cannot find field." — which was breaking tier creation
        and cascading into empty bidding sections + 1/5 waterfall lines.
        """
        parent = f"accounts/{self.get_publisher_id()}"
        fmt_map = {
            "BANNER": "BANNER",
            "INTERSTITIAL": "INTERSTITIAL",
            "REWARDED": "REWARDED",
            "REWARDED_INTERSTITIAL": "REWARDED_INTERSTITIAL",
            "NATIVE": "NATIVE",
            "APP_OPEN": "APP_OPEN_AD",
            "APP_OPEN_AD": "APP_OPEN_AD",
        }
        admob_format = fmt_map.get((ad_format or "").upper(),
                                   (ad_format or "BANNER").upper())
        body: dict = {
            "appId": app_id_full,
            "displayName": display_name[:80],
            "adFormat": admob_format,
        }
        ad_types_default = {
            "BANNER": ["RICH_MEDIA", "VIDEO"],
            "INTERSTITIAL": ["RICH_MEDIA", "VIDEO"],
            "REWARDED": ["RICH_MEDIA", "VIDEO"],
            "REWARDED_INTERSTITIAL": ["VIDEO"],
            "NATIVE": ["RICH_MEDIA", "VIDEO"],
            "APP_OPEN_AD": ["RICH_MEDIA", "VIDEO"],
        }
        body["adTypes"] = ad_types_default.get(admob_format, ["RICH_MEDIA", "VIDEO"])
        if admob_format in ("REWARDED", "REWARDED_INTERSTITIAL"):
            body["rewardSettings"] = {
                "rewardAmount": "1",
                "rewardItem": "reward",
            }
        return self._with_quota_retry(
            lambda: self.service_alpha.accounts().adUnits().create(
                parent=parent, body=body,
            ).execute()
        )

    # ========================================================================
    # (Third-party adapter helpers — kept for /networks UI parity)
    # ========================================================================
    def resolve_adapter_for_network(self, network_code: str, platform: str,
                                     ad_format: str | None = None,
                                     for_bidding: bool = False) -> dict | None:
        """Resolve the adapter for (network, platform, ad_format). When
        `for_bidding` is True, look up adapters under the NETWORK's BIDDING
        ad source (separate from waterfall) — required for LIVE bidding
        lines and their mappings."""
        source_id = (self.find_bidding_source_id_for_network(network_code)
                     if for_bidding
                     else self.find_source_id_for_network(network_code))
        if not source_id:
            return None
        try:
            adapters = self.list_adapters_for_source(source_id)
        except AdMobAPIError:
            return None
        target_plat = (platform or "").upper()
        target_fmt = (ad_format or "").upper()
        # AdMob uses slightly different names for App Open depending on the
        # API version / surface — match all variants.
        fmt_aliases = {
            "APP_OPEN":     {"APP_OPEN", "APP_OPEN_AD", "APPOPEN"},
            "APP_OPEN_AD":  {"APP_OPEN", "APP_OPEN_AD", "APPOPEN"},
        }
        target_fmts = fmt_aliases.get(target_fmt, {target_fmt} if target_fmt else set())
        # First pass: match on platform AND format
        if target_fmt:
            for ad in adapters:
                if (ad.get("platform") or "").upper() != target_plat:
                    continue
                ad_fmts = {(f or "").upper() for f in (ad.get("formats") or [])}
                if target_fmts & ad_fmts:
                    return ad
            # STRICT: when caller specified a format, do NOT silently fall back
            # to a different-format adapter. Returning a mismatched adapter
            # was the root cause of "Mediation group line CPM mode unsupported"
            # (the resulting LIVE bidding line was structurally invalid for
            # the source ad unit's format). Returning None lets the caller
            # cleanly skip this network with a clear error.
            return None
        # No format requested → platform-only.
        for ad in adapters:
            if (ad.get("platform") or "").upper() == target_plat:
                return ad
        return adapters[0] if adapters else None

    def build_admob_config_payload(
        self,
        network_code: str,
        platform: str,
        user_fields: dict,
        ad_format: str | None = None,
        for_bidding: bool = False,
    ) -> tuple[str, dict, list[str]]:
        adapter = self.resolve_adapter_for_network(
            network_code, platform, ad_format, for_bidding=for_bidding)
        if adapter is None:
            raise AdMobAPIError(
                f"{network_code} does not support {ad_format or '(no format)'} "
                f"bidding on {platform} — no matching AdMob adapter "
                f"exists. Skipping this network for this group."
            )
        adapter_id = str(adapter.get("adapterId", ""))
        metadata = adapter.get("adapterConfigMetadata", []) or []
        cat = NETWORK_BY_CODE.get(network_code.upper(), {})
        all_field_specs = (cat.get("app_fields") or []) + (cat.get("ad_unit_fields") or [])
        configs: dict[str, str] = {}
        warnings: list[str] = []
        for spec in all_field_specs:
            value = user_fields.get(spec["key"])
            if not value:
                continue
            label = spec["label"].lower()
            key_norm = spec["key"].replace("_", "").lower()
            matched_id = None
            for md in metadata:
                md_label = (md.get("adapterConfigMetadataLabel") or "").lower()
                md_label_norm = md_label.replace(" ", "").replace("_", "")
                if (label in md_label or md_label in label
                        or key_norm in md_label_norm or md_label_norm in key_norm):
                    matched_id = str(md.get("adapterConfigMetadataId", ""))
                    break
            if matched_id:
                configs[matched_id] = str(value)
            else:
                warnings.append(
                    f"Could not map field '{spec['label']}' to any AdMob adapter "
                    f"metadata for {network_code}."
                )
        return adapter_id, configs, warnings

    def create_ad_unit_mapping_in_admob(
        self,
        ad_unit_id: str,
        network_code: str,
        platform: str,
        display_name: str,
        user_fields: dict,
        ad_format: str | None = None,
        for_bidding: bool = False,
    ) -> tuple[dict, list[str]]:
        adapter_id, configs, warnings = self.build_admob_config_payload(
            network_code=network_code, platform=platform,
            user_fields=user_fields, ad_format=ad_format,
            for_bidding=for_bidding,
        )
        if not configs:
            raise AdMobAPIError(
                f"No usable configuration values for {network_code} on {platform}."
            )
        short_id = ad_unit_id.split("/")[-1] if "/" in ad_unit_id else ad_unit_id
        parent = f"accounts/{self.get_publisher_id()}/adUnits/{short_id}"
        # `name` is output-only on AdUnitMapping; user-supplied labels go in
        # `displayName`.
        body = {
            "displayName": display_name[:80],
            "adapterId": adapter_id,
            "adUnitConfigurations": configs,
            "state": "ENABLED",
        }
        try:
            resp = self.service_alpha.accounts().adUnits().adUnitMappings().create(
                parent=parent, body=body,
            ).execute()
            return resp, warnings
        except HttpError as e:
            raise AdMobAPIError(_format_http_error(e)) from e

    # ========================================================================
    # MEDIATION GROUPS
    # ========================================================================
    def export_group_config(self, group: MediationGroup) -> dict:
        return {
            "name": group.name,
            "ad_format": group.ad_format,
            "platform": group.platform,
            "status": group.status,
            "targeting": {
                "country_mode": group.country_mode,
                "countries": group.countries or [],
                "ad_unit_id": group.target_ad_unit_id,
                "ad_unit_name": group.target_ad_unit_name,
            },
            "floor_type": group.floor_type,
            "base_avg_ecpm_usd": group.base_avg_ecpm,
            "report_metrics_snapshot": group.report_metrics or {},
            "admob_group_id": group.admob_group_id,
            "admob_group_name": group.admob_group_name,
            "waterfall": [
                {"priority": l.priority, "line_name": l.line_name,
                 "ecpm_usd": l.ecpm_usd, "enabled": l.enabled,
                 "network_code": l.network_code, "cpm_mode": l.cpm_mode}
                for l in sorted(group.waterfall_lines, key=lambda x: x.priority)
            ],
        }

    def list_mediation_groups_in_admob(self) -> list[dict]:
        parent = f"accounts/{self.get_publisher_id()}"
        try:
            resp = self.service_alpha.accounts().mediationGroups().list(
                parent=parent, pageSize=200,
            ).execute()
        except HttpError as e:
            raise AdMobAPIError(_format_http_error(e)) from e
        out = []
        for g in resp.get("mediationGroups", []) or []:
            targeting = g.get("targeting", {}) or {}
            out.append({
                "mediation_group_id": g.get("mediationGroupId", "") or g.get("name", "").split("/")[-1],
                "name_full": g.get("name", ""),
                "display_name": g.get("displayName", ""),
                "platform": targeting.get("platform", ""),
                "format": targeting.get("format", ""),
                "state": g.get("state", ""),
                "ad_unit_ids": targeting.get("adUnitIds", []) or [],
                "country_codes": targeting.get("targetedRegionCodes", []) or [],
                "line_count": len(g.get("mediationGroupLines", {}) or {}),
            })
        return out

    # ========================================================================
    # CLEANUP — delete ad units / disable mediation groups
    # ========================================================================
    def batch_delete_ad_units(self, ad_unit_ids: list[str],
                              dry_run: bool = False) -> dict:
        """Hard-delete ad units via v1alpha `adUnits:batchDelete`.

        `ad_unit_ids` are full ids of the form 'ca-app-pub-XXXX/YYYY'. AdMob
        deletes the unit and any waterfall/bidding mappings hanging off it.
        Sent in chunks so a large selection doesn't blow the request limit.
        Returns {"deleted": <n>} (0 when dry_run)."""
        if self.service_alpha is None:
            raise AdMobAPIError(
                "AdMob v1alpha service not available — discovery doc "
                "fetch failed at startup")
        ids = [u for u in ad_unit_ids if u]
        if not ids:
            return {"deleted": 0}
        parent = f"accounts/{self.get_publisher_id()}"
        deleted = 0
        CHUNK = 100
        for i in range(0, len(ids), CHUNK):
            chunk = ids[i:i + CHUNK]
            self._with_quota_retry(
                lambda c=chunk: self.service_alpha.accounts().adUnits().batchDelete(
                    parent=parent,
                    body={"adUnitIds": c, "dryRun": dry_run},
                ).execute()
            )
            if not dry_run:
                deleted += len(chunk)
        return {"deleted": deleted}

    def disable_mediation_group(self, group_id: str) -> dict:
        """Stop a mediation group from serving.

        The AdMob API exposes NO hard-delete for mediation groups (the
        resource only supports list/create/patch). The closest equivalent —
        and what the AdMob UI's "remove" effectively does for API clients —
        is patching `state` to DISABLED: the group stops serving ads and
        collecting stats, and can later be re-enabled. Returns the patched
        group resource."""
        if self.service_alpha is None:
            raise AdMobAPIError(
                "AdMob v1alpha service not available — discovery doc "
                "fetch failed at startup")
        name = (f"accounts/{self.get_publisher_id()}"
                f"/mediationGroups/{group_id}")
        return self._with_quota_retry(
            lambda: self.service_alpha.accounts().mediationGroups().patch(
                name=name, body={"state": "DISABLED"}, updateMask="state",
            ).execute()
        )

    def patch_lines_into_group(
        self,
        mediation_group_id: str,
        admob_manual_ecpms: list[float],
    ) -> tuple[dict, int]:
        positive = sorted([e for e in admob_manual_ecpms if e and e > 0], reverse=True)
        if not positive:
            raise AdMobAPIError("No positive eCPM lines provided")
        last_exc: AdMobAPIError | None = None
        for n in range(len(positive), 0, -1):
            try:
                resp = self._patch_lines_body(mediation_group_id, positive[:n])
                return resp, n
            except AdMobAPIError as e:
                msg = str(e).lower()
                if "max allowed" in msg and "admob network" in msg:
                    last_exc = e
                    continue
                raise
        if last_exc:
            raise last_exc
        raise AdMobAPIError("Unknown error patching mediation group")

    def _patch_lines_body(self, mediation_group_id: str, ecpms: list[float]) -> dict:
        waterfall_source_id = self.get_admob_waterfall_source_id()
        new_lines: dict[str, dict] = {}
        update_mask_paths: list[str] = []
        for i, ecpm in enumerate(ecpms, start=1):
            line_id = f"-{i}"
            cpm_micros = int(round(ecpm * 1_000_000))
            new_lines[line_id] = {
                "displayName": f"Line {i} - ${ecpm:.2f}",
                "adSourceId": waterfall_source_id,
                "cpmMode": "MANUAL",
                "cpmMicros": str(cpm_micros),
                "state": "ENABLED",
            }
            # v1alpha FieldMask uses BRACKETED syntax for map subfields:
            # `mediationGroupLines["-1"].cpm_micros` (camelCase parent +
            # bracketed key + snake_case leaf). Verified live earlier.
            update_mask_paths.append(f'mediationGroupLines["{line_id}"].cpm_micros')
            update_mask_paths.append(f'mediationGroupLines["{line_id}"].cpm_mode')
            update_mask_paths.append(f'mediationGroupLines["{line_id}"].display_name')
            update_mask_paths.append(f'mediationGroupLines["{line_id}"].state')
            update_mask_paths.append(f'mediationGroupLines["{line_id}"].ad_source_id')
        body = {"mediationGroupLines": new_lines}
        name = f"accounts/{self.get_publisher_id()}/mediationGroups/{mediation_group_id}"
        try:
            return self.service_alpha.accounts().mediationGroups().patch(
                name=name,
                body=body,
                updateMask=",".join(update_mask_paths),
            ).execute()
        except HttpError as e:
            raise AdMobAPIError(_format_http_error(e)) from e

    def _count_lines_in_response(self, mg_resp: dict) -> dict:
        result = {"manual": 0, "live": 0}
        for line in (mg_resp.get("mediationGroupLines", {}) or {}).values():
            mode = (line.get("cpmMode") or "").upper()
            if mode == "MANUAL":
                result["manual"] += 1
            elif mode in ("LIVE", "OPTIMIZED"):
                result["live"] += 1
        return result

    def create_mediation_group_in_admob(
        self,
        display_name: str,
        platform: str,
        ad_format: str,
        targeting_ad_unit_ids: list[str],
        country_codes: list[str],
        manual_lines: list[dict],
        bidding_lines: list[dict] | None = None,
    ) -> tuple[dict, int, int, int]:
        """Create a mediation group in ONE call.

        `targeting_ad_unit_ids` = the SOURCE/placement ad unit(s) the group
        serves. `manual_lines` and `bidding_lines` are fully-built line
        dicts (each already carrying displayName / adSourceId / cpmMode /
        cpmMicros / state / adUnitMappings as needed).

        Returns (response, manual_actual, live_actual, manual_requested).
        """
        requested_manual = len(manual_lines)
        lines: dict[str, dict] = {}
        key = 1
        for ml in manual_lines:
            lines[f"-{key}"] = ml
            key += 1
        for bl in (bidding_lines or []):
            lines[f"-{key}"] = bl
            key += 1

        # v1alpha mediationGroups.create accepts "APP_OPEN" (NO "_AD" suffix)
        # — v1beta's "APP_OPEN_AD" was being rejected with "Format must be one
        # of the supported formats". Normalise APP_OPEN_AD → APP_OPEN for the
        # v1alpha enum.
        admob_format = (ad_format or "").upper()
        if admob_format == "APP_OPEN_AD":
            admob_format = "APP_OPEN"
        targeting: dict = {
            "platform": platform.upper(),
            "format": admob_format,
            "adUnitIds": [x for x in targeting_ad_unit_ids if x],
        }
        if country_codes:
            targeting["targetedRegionCodes"] = country_codes
        body: dict = {
            "displayName": display_name[:80],
            "state": "ENABLED",
            "targeting": targeting,
        }
        if lines:
            body["mediationGroupLines"] = lines
        parent = f"accounts/{self.get_publisher_id()}"
        # Use v1alpha (the one we've verified end-to-end), not v1beta. v1beta
        # was rejecting APP_OPEN_AD; v1alpha cleanly accepts APP_OPEN.
        if self.service_alpha is None:
            raise AdMobAPIError(
                "v1alpha service not available — needed for mediationGroups.create")
        resp = self._with_quota_retry(
            lambda: self.service_alpha.accounts().mediationGroups().create(
                parent=parent, body=body,
            ).execute()
        )
        counts = self._count_lines_in_response(resp)
        return resp, counts["manual"], counts["live"], requested_manual


# ============================================================================
# TEMPLATES + STATIC ASSETS
# ============================================================================
TEMPLATE_FILES: dict[str, str] = {}
CSS_CONTENT = ""

TEMPLATE_FILES["base.html"] = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{% block title %}Flow{% endblock %}</title>
  <meta name="color-scheme" content="light dark">
  <script>
    // Set theme before first paint to avoid a flash. Default = light.
    (function(){ try {
      var t = localStorage.getItem("flow-theme") || "light";
      document.documentElement.setAttribute("data-theme", t);
    } catch(e){ document.documentElement.setAttribute("data-theme","light"); } })();
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/static/style.css?v={{ app_version }}" />
</head>
<body>
  <header class="topbar">
    <div class="brand"><a href="/" class="brand-link"><span class="brand-mark">⌬</span><span class="brand-name">Flow</span></a></div>
    <nav class="topnav">
      {% if user and user.id %}
        <a href="/dashboard">Dashboard</a>
        <a href="/apps">Apps</a>
        <a href="/networks">Networks</a>
        <a href="/bidding">Bidding</a>
        <a href="/mediation">Mediation</a>
        <a href="/cleanup">Cleanup</a>
        <a href="/mediation/builder" class="cta">+ Builder</a>
        <span class="sep"></span>
        <span class="user-chip">{% if user.picture %}<img src="{{ user.picture }}" alt="" />{% endif %}<span>{{ user.email }}</span></span>
        <a href="/auth/logout" class="logout">Sign out</a>
      {% endif %}
      <button type="button" class="theme-toggle" id="theme-toggle" title="Toggle light / dark" aria-label="Toggle light or dark theme"><span class="icon-light">🌙</span><span class="icon-dark">☀️</span></button>
    </nav>
  </header>
  <main class="content">{% block content %}{% endblock %}</main>
  <footer class="footer"><span>Flow</span><span class="footer-sep">·</span><a href="/changelog" class="footer-version" title="What's new — click for the changelog">v{{ app_version }}</a><span class="footer-sep">·</span><span>Build AdMob mediation waterfalls in a few clicks.</span></footer>
  <script>
    // ---- Theme toggle (persisted) ----
    (function(){
      var btn = document.getElementById("theme-toggle");
      if (!btn) return;
      btn.addEventListener("click", function(){
        var cur = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
        var next = cur === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        try { localStorage.setItem("flow-theme", next); } catch(e){}
      });
    })();
    // ---- M3 dialog helper: window.m3confirm(opts) -> Promise<bool> ----
    // Clean replacement for native confirm()/alert(). Usage:
    //   m3confirm({title, message, confirmText, danger}).then(ok => { ... })
    window.m3confirm = function(opts){
      opts = opts || {};
      return new Promise(function(resolve){
        var scrim = document.createElement("div");
        scrim.className = "m3-scrim";
        var confirmText = opts.confirmText || "Confirm";
        var cancelText = opts.cancelText || "Cancel";
        var confirmCls = opts.danger ? "btn-danger" : "btn-primary";
        var d = document.createElement("div");
        d.className = "m3-dialog";
        d.setAttribute("role","dialog"); d.setAttribute("aria-modal","true");
        var h = document.createElement("h3"); h.textContent = opts.title || "Are you sure?";
        var p = document.createElement("p"); p.textContent = opts.message || "";
        var acts = document.createElement("div"); acts.className = "m3-dialog-actions";
        d.appendChild(h); if (opts.message) d.appendChild(p); d.appendChild(acts);
        function close(val){ scrim.classList.remove("show"); setTimeout(function(){ scrim.remove(); }, 200); resolve(val); }
        if (!opts.alert){
          var cancel = document.createElement("button");
          cancel.type = "button"; cancel.className = "btn-ghost"; cancel.textContent = cancelText;
          cancel.addEventListener("click", function(){ close(false); });
          acts.appendChild(cancel);
        }
        var ok = document.createElement("button");
        ok.type = "button"; ok.className = confirmCls; ok.textContent = opts.alert ? (opts.confirmText || "OK") : confirmText;
        ok.addEventListener("click", function(){ close(true); });
        acts.appendChild(ok);
        scrim.appendChild(d); document.body.appendChild(scrim);
        scrim.addEventListener("click", function(e){ if (e.target === scrim && !opts.alert) close(false); });
        requestAnimationFrame(function(){ scrim.classList.add("show"); ok.focus(); });
      });
    };
    // Convenience alert-style toast/dialog
    window.m3alert = function(message, title){ return window.m3confirm({title: title || "Notice", message: message, alert: true, confirmText: "OK"}); };
  </script>
</body>
</html>"""

TEMPLATE_FILES["login.html"] = r"""{% extends "base.html" %}
{% block title %}Sign in · Flow{% endblock %}
{% block content %}
<section class="login-wrap">
  <div class="login-card">
    <p class="eyebrow">AdMob mediation, made simple</p>
    <h1 class="display">Connect your <em>AdMob</em> account.</h1>
    <p class="lede">Sign in with Google and Flow loads your apps, ad units, and last-7-day earnings. Then it builds your mediation waterfalls for you — no manual setup in AdMob.</p>
    <a class="btn-primary" href="/auth/login"><span class="g-mark"><svg viewBox="0 0 48 48" width="18" height="18" aria-hidden="true" focusable="false"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg></span>Continue with Google</a>
    <p class="fineprint">Flow only asks for the AdMob permissions it needs to read your reports and set up mediation. Your credentials stay encrypted.</p>
  </div>
  <aside class="login-side">
    <h3>How it works</h3>
    <ol>
      <li>Sign in with Google</li>
      <li>Sync your apps &amp; ad units</li>
      <li>Pick an app and its ad units</li>
      <li>Choose countries &amp; waterfall depth</li>
      <li>Fetch live earnings (last 7 days)</li>
      <li>Flow calculates the waterfall for you</li>
      <li>One click builds it all in AdMob</li>
    </ol>
  </aside>
</section>
{% endblock %}"""

TEMPLATE_FILES["dashboard.html"] = r"""{% extends "base.html" %}
{% block title %}Dashboard · Flow{% endblock %}
{% block content %}
<section class="page-head"><p class="eyebrow">Dashboard</p><h1 class="display">Welcome, {{ user.name or user.email }}.</h1></section>
{% if api_error %}<div class="alert alert-warn"><strong>AdMob API:</strong> {{ api_error }}</div>{% endif %}
<section class="grid grid-4 stat-row">
  <article class="card"><p class="card-label">Publisher ID</p><p class="card-value mono" style="font-size:15px">{{ publisher_id }}</p></article>
  <article class="card"><p class="card-label">Cached apps</p><p class="card-value">{{ app_count }}</p><a class="card-link" href="/apps">Manage →</a></article>
  <article class="card"><p class="card-label">Ad units</p><p class="card-value">{{ stats.adunit_count }}</p></article>
  <article class="card"><p class="card-label">Mediation groups</p><p class="card-value">{{ group_count }}</p><a class="card-link" href="/mediation">Open →</a></article>
</section>
{% if accounts %}
<section class="card acct-card">
  <div class="acct-head">
    <p class="card-label" style="margin:0">AdMob account{% if accounts|length > 1 %} <span class="muted small">· used in the Builder</span>{% endif %}</p>
    {% if accounts|length > 1 %}
    <details class="m3-menu" id="acct-menu">
      <summary class="m3-menu-btn"><span id="acct-summary">All accounts</span><span class="chev">▾</span></summary>
      <div class="m3-menu-list">
        <input type="text" id="acct-search" placeholder="Search accounts…" />
        <div id="acct-options"></div>
      </div>
    </details>
    {% endif %}
  </div>
  {% if accounts|length == 1 %}
  <div class="acct-single"><span class="country-chip is-selected">{{ accounts[0].publisher }}</span><span class="muted small">{{ accounts[0].app_count }} app{{ '' if accounts[0].app_count == 1 else 's' }}</span></div>
  <p class="muted small" style="margin-bottom:0">Have another account? Add it on admob.google.com, then <a href="/apps">Sync</a>.</p>
  {% else %}
  <p class="muted small" style="margin-bottom:0">Choose which accounts' apps appear in the Builder.</p>
  {% endif %}
</section>
{% if accounts|length > 1 %}
<script>
(function(){
  const ACCOUNTS = {{ accounts|tojson }};
  let sel = new Set();
  try { (JSON.parse(localStorage.getItem("selectedPublishers")||"[]")||[]).forEach(p=>sel.add(p)); } catch(e){}
  const valid = new Set(ACCOUNTS.map(a=>a.publisher));
  sel = new Set([...sel].filter(p=>valid.has(p)));
  if (sel.size===0) ACCOUNTS.forEach(a=>sel.add(a.publisher));
  function save(){ try{ localStorage.setItem("selectedPublishers", JSON.stringify([...sel])); }catch(e){} }
  function summary(){
    const s = document.getElementById("acct-summary");
    if (!s) return;
    if (sel.size === ACCOUNTS.length) s.textContent = "All accounts (" + ACCOUNTS.length + ")";
    else if (sel.size === 1) s.textContent = [...sel][0];
    else s.textContent = sel.size + " accounts selected";
  }
  function render(){
    const wrap = document.getElementById("acct-options");
    const se = document.getElementById("acct-search");
    const f = ((se ? se.value : "")||"").toLowerCase();
    wrap.innerHTML = "";
    ACCOUNTS.filter(a => !f || a.publisher.toLowerCase().includes(f)).forEach(a => {
      const on = sel.has(a.publisher);
      const item = document.createElement("label");
      item.className = "m3-menu-item";
      const cb = document.createElement("input"); cb.type = "checkbox"; cb.checked = on;
      const name = document.createElement("span"); name.textContent = a.publisher;
      const cnt = document.createElement("span"); cnt.className = "muted small"; cnt.textContent = a.app_count;
      cb.addEventListener("change", () => {
        if (sel.has(a.publisher)) sel.delete(a.publisher); else sel.add(a.publisher);
        if (sel.size===0) ACCOUNTS.forEach(x=>sel.add(x.publisher));
        save(); summary(); render();
      });
      item.appendChild(cb); item.appendChild(name); item.appendChild(cnt);
      wrap.appendChild(item);
    });
  }
  const se = document.getElementById("acct-search");
  if (se) se.addEventListener("input", render);
  save(); summary(); render();
})();
</script>
{% endif %}
{% endif %}

{% if group_count or app_count %}
<section class="dash-charts grid grid-2">
  <div class="card chart-card">
    <p class="card-label">Mediation groups by format</p>
    {% if stats.formats %}
    <div class="bar-chart">
      {% for b in stats.formats %}
      <div class="bar-row">
        <span class="bar-label">{{ b.label|replace('_',' ')|title }}</span>
        <span class="bar-track"><span class="bar-fill" style="width:{{ b.pct }}%"></span></span>
        <span class="bar-val">{{ b.value }}</span>
      </div>
      {% endfor %}
    </div>
    {% else %}<p class="muted small">No mediation groups yet. Open the Builder to create your first one.</p>{% endif %}
  </div>
  <div class="card chart-card">
    <p class="card-label">Apps by platform</p>
    {% if stats.platforms %}
    <div class="bar-chart">
      {% for b in stats.platforms %}
      <div class="bar-row">
        <span class="bar-label">{{ b.label|title }}</span>
        <span class="bar-track"><span class="bar-fill" style="width:{{ b.pct }}%"></span></span>
        <span class="bar-val">{{ b.value }}</span>
      </div>
      {% endfor %}
    </div>
    {% else %}<p class="muted small">No apps synced yet.</p>{% endif %}
    <p class="card-label" style="margin-top:20px">Push status</p>
    <div class="status-split">
      <div class="split-seg split-pushed" style="flex:{{ stats.pushed or 0 }}"><span>{{ stats.pushed }}</span></div>
      <div class="split-seg split-draft" style="flex:{{ stats.draft or 0 }}"><span>{{ stats.draft }}</span></div>
    </div>
    <div class="split-legend">
      <span><i class="dot dot-pushed"></i> {{ stats.pushed }} live in AdMob</span>
      <span><i class="dot dot-draft"></i> {{ stats.draft }} draft</span>
    </div>
  </div>
</section>
{% endif %}
<section class="cta-row">
  <a class="btn-primary" href="/mediation/builder">▶ Open Mediation Builder</a>
  <form method="post" action="/apps/sync" style="display:inline"><button type="submit" class="btn-secondary">↻ Sync Apps + Ad Units</button></form>
  <a class="btn-danger" href="/cleanup">🗑 Delete Ad Units &amp; Groups</a>
</section>
<section class="workflow">
  <h2 class="section-title">How it works</h2>
  <ol class="workflow-steps">
    <li><span class="step-no">01</span><span class="step-text">Sign in <span class="done">✓</span></span></li>
    <li><span class="step-no">02</span><span class="step-text">Sync your apps &amp; ad units <a href="/apps">→ Apps</a></span></li>
    <li><span class="step-no">03</span><span class="step-text">Open the Builder <a href="/mediation/builder">→ Builder</a></span></li>
    <li><span class="step-no">04</span><span class="step-text">Pick an app and one or more ad units</span></li>
    <li><span class="step-no">05</span><span class="step-text">Choose which countries to target</span></li>
    <li><span class="step-no">06</span><span class="step-text">Set how many waterfall tiers you want (1–{{ max_lines }})</span></li>
    <li><span class="step-no">07</span><span class="step-text">Fetch live earnings from AdMob (last 7 days)</span></li>
    <li><span class="step-no">08</span><span class="step-text">Review the tier eCPM values Flow calculated</span></li>
    <li><span class="step-no">09</span><span class="step-text">Push — Flow builds the tier ad units and mediation groups in AdMob for you</span></li>
    <li><span class="step-no">10</span><span class="step-text">Flow double-checks every line and flags anything disabled</span></li>
  </ol>
</section>
{% endblock %}"""

TEMPLATE_FILES["cleanup.html"] = r"""{% extends "base.html" %}
{% block title %}Cleanup · Flow{% endblock %}
{% block content %}
<section class="page-head">
  <p class="eyebrow">Cleanup</p>
  <h1 class="display">Delete ad units &amp; mediation groups</h1>
  <p class="lede">Pick an app to see everything in it, then delete the ad units or groups you no longer need.</p>
</section>

{% if not apps %}
<div class="empty"><p>No apps cached yet. Sync first.
  <form method="post" action="/apps/sync" style="display:inline"><button class="btn-primary" type="submit">↻ Sync from AdMob</button></form></p></div>
{% else %}
<div class="alert alert-warn" style="margin-bottom:20px">
  <strong>Before you delete:</strong> Ad units are <strong>permanently removed</strong> from AdMob. Mediation groups can't be deleted through AdMob, so Flow <strong>disables</strong> them instead — they stop serving and you can turn them back on later.
</div>

<section class="card" style="margin-bottom:18px">
  <p class="card-label">Select app</p>
  <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:8px">
    <select id="app-select" style="min-width:280px;padding:10px;border-radius:8px;background:var(--bg-3);color:var(--ink);border:1px solid var(--line-2);color-scheme:dark">
      <option value="">— choose an app —</option>
      {% for app in apps %}<option value="{{ app.id }}">{{ app.name or app.app_id }} · {{ app.platform }}</option>{% endfor %}
    </select>
    <button class="btn-secondary" id="load-btn" type="button">Load inventory</button>
    <span id="sync-note" class="small mono"></span>
  </div>
</section>

<div id="inventory" style="display:none">
  <section style="margin-bottom:24px">
    <h2 class="section-title">Ad units (<span id="au-count">0</span>)</h2>
    <label style="display:inline-flex;gap:8px;align-items:center;margin:6px 0 10px"><input type="checkbox" id="au-all"> <strong>Select all ad units</strong></label>
    <table class="table">
      <thead><tr><th style="width:36px"></th><th>Name</th><th>Format</th><th>Ad unit ID</th></tr></thead>
      <tbody id="au-body"></tbody>
    </table>
    <p id="au-empty" class="small" style="display:none">No ad units cached for this app.</p>
  </section>

  <section style="margin-bottom:24px">
    <h2 class="section-title">Mediation groups (<span id="mg-count">0</span>)</h2>
    <label style="display:inline-flex;gap:8px;align-items:center;margin:6px 0 10px"><input type="checkbox" id="mg-all"> <strong>Select all groups</strong></label>
    <table class="table">
      <thead><tr><th style="width:36px"></th><th>Name</th><th>Format</th><th>Platform</th><th>Lines</th><th>State</th></tr></thead>
      <tbody id="mg-body"></tbody>
    </table>
    <p id="mg-empty" class="small" style="display:none">No mediation groups cached for this app.</p>
  </section>

  <section class="cta-row">
    <button class="btn-danger" id="delete-btn" type="button" disabled>🗑 Delete selected</button>
    <span id="status-msg" class="small"></span>
  </section>
  <pre id="result-box" class="mono small" style="display:none;white-space:pre-wrap;margin-top:14px;padding:14px;border:1px solid var(--line);border-radius:8px;background:rgba(0,0,0,0.15)"></pre>
</div>

<script>
(function(){
  var $ = function(id){ return document.getElementById(id); };
  var current = null;

  function selectedUnitIds(){
    return Array.prototype.slice.call(document.querySelectorAll(".au-cb:checked")).map(function(c){ return c.dataset.id; });
  }
  function selectedGroupIds(){
    return Array.prototype.slice.call(document.querySelectorAll(".mg-cb:checked")).map(function(c){ return c.dataset.id; });
  }
  function refreshDeleteBtn(){
    $("delete-btn").disabled = (selectedUnitIds().length + selectedGroupIds().length) === 0;
  }
  function esc(s){ var d = document.createElement("div"); d.textContent = (s == null ? "" : String(s)); return d.innerHTML; }

  function load(){
    var id = $("app-select").value;
    if(!id){ $("inventory").style.display = "none"; return; }
    $("load-btn").disabled = true; $("sync-note").textContent = "Loading…";
    fetch("/cleanup/inventory/" + id).then(function(r){ return r.json(); }).then(function(data){
      current = data;
      $("sync-note").textContent = "Last synced: " + (data.app.last_synced_at || "never");
      var aub = $("au-body"); aub.innerHTML = "";
      (data.ad_units || []).forEach(function(u){
        var tr = document.createElement("tr");
        tr.innerHTML = '<td><input type="checkbox" class="au-cb" data-id="' + esc(u.ad_unit_id) + '"></td>' +
          '<td>' + esc(u.name) + '</td><td><span class="pill">' + esc(u.ad_format) + '</span></td>' +
          '<td class="mono small">' + esc(u.ad_unit_id) + '</td>';
        aub.appendChild(tr);
      });
      $("au-count").textContent = (data.ad_units || []).length;
      $("au-empty").style.display = (data.ad_units || []).length ? "none" : "block";

      var mgb = $("mg-body"); mgb.innerHTML = "";
      (data.groups || []).forEach(function(g){
        var dis = (g.state === "DISABLED");
        var tr = document.createElement("tr");
        tr.innerHTML = '<td><input type="checkbox" class="mg-cb" data-id="' + esc(g.group_id) + '"' + (dis ? " disabled" : "") + '></td>' +
          '<td>' + esc(g.display_name) + '</td><td><span class="pill">' + esc(g.ad_format) + '</span></td>' +
          '<td>' + esc(g.platform) + '</td><td>' + esc(g.line_count) + '</td>' +
          '<td>' + (dis ? '<span class="pill">DISABLED</span>' : esc(g.state)) + '</td>';
        mgb.appendChild(tr);
      });
      $("mg-count").textContent = (data.groups || []).length;
      $("mg-empty").style.display = (data.groups || []).length ? "none" : "block";

      $("au-all").checked = false; $("mg-all").checked = false;
      $("inventory").style.display = "block";
      $("result-box").style.display = "none";
      refreshDeleteBtn();
    }).catch(function(e){ $("sync-note").textContent = "Failed to load: " + e; })
      .finally(function(){ $("load-btn").disabled = false; });
  }

  document.addEventListener("change", function(e){
    if(e.target.id === "au-all"){
      document.querySelectorAll(".au-cb").forEach(function(c){ c.checked = e.target.checked; });
    } else if(e.target.id === "mg-all"){
      document.querySelectorAll(".mg-cb:not([disabled])").forEach(function(c){ c.checked = e.target.checked; });
    }
    if(e.target.classList && (e.target.classList.contains("au-cb") || e.target.classList.contains("mg-cb"))){
      refreshDeleteBtn();
    } else if(e.target.id === "au-all" || e.target.id === "mg-all"){
      refreshDeleteBtn();
    }
  });

  $("load-btn").addEventListener("click", load);

  $("delete-btn").addEventListener("click", function(){
    var units = selectedUnitIds(), groups = selectedGroupIds();
    if(units.length + groups.length === 0){ return; }
    var msg = "Delete " + units.length + " ad unit(s) (PERMANENT) and disable " + groups.length + " mediation group(s)?";
    if(!confirm(msg)){ return; }
    $("delete-btn").disabled = true; $("status-msg").textContent = "Working…";
    fetch("/cleanup/delete", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ app_db_id: parseInt($("app-select").value, 10), ad_unit_ids: units, group_ids: groups })
    }).then(function(r){ return r.json(); }).then(function(res){
      $("status-msg").textContent = (res.status === "ok" ? "✓ Done" : "⚠ Completed with issues");
      var box = $("result-box");
      box.style.display = "block"; box.textContent = JSON.stringify(res, null, 2);
      load();
    }).catch(function(e){ $("status-msg").textContent = "Failed: " + e; })
      .finally(function(){ refreshDeleteBtn(); });
  });
})();
</script>
{% endif %}
{% endblock %}"""

TEMPLATE_FILES["changelog.html"] = r"""{% extends "base.html" %}
{% block title %}Changelog · Flow{% endblock %}
{% block content %}
<section class="page-head">
  <p class="eyebrow">Changelog</p>
  <h1 class="display">What's new in <em>Flow</em></h1>
  <p class="lede">Every release and exactly what changed. You're on <b>v{{ app_version }}</b>.</p>
</section>
<div class="changelog">
  {% for rel in changelog %}
  <article class="changelog-entry{% if rel.version == app_version %} is-current{% endif %}">
    <div class="changelog-head">
      <span class="changelog-ver">v{{ rel.version }}</span>
      {% if rel.version == app_version %}<span class="pill pill-good">current</span>{% endif %}
      <span class="changelog-title">{{ rel.title }}</span>
      <span class="changelog-date mono small">{{ rel.date }}</span>
    </div>
    <ul class="changelog-list">
      {% for c in rel.changes %}<li>{{ c }}</li>{% endfor %}
    </ul>
  </article>
  {% endfor %}
</div>
{% endblock %}"""

TEMPLATE_FILES["apps.html"] = r"""{% extends "base.html" %}
{% block title %}Apps · Flow{% endblock %}
{% block content %}
<section class="page-head row-between">
  <div><p class="eyebrow">Apps</p><h1 class="display">Your AdMob apps</h1></div>
  <form method="post" action="/apps/sync"><button class="btn-secondary" type="submit">↻ Sync from AdMob</button></form>
</section>
{% if apps %}
<table class="table">
  <thead><tr><th>Name</th><th>Platform</th><th>AdMob App ID</th><th>Store ID</th><th>Ad units</th><th></th></tr></thead>
  <tbody>
    {% for app in apps %}
    <tr>
      <td>{{ app.name or "(unnamed)" }}</td>
      <td><span class="pill pill-{{ app.platform|lower }}">{{ app.platform }}</span></td>
      <td class="mono small">{{ app.app_id }}</td>
      <td class="mono small">{{ app.package_name or "—" }}</td>
      <td>{{ app.ad_units|length }}</td>
      <td><a href="/apps/{{ app.id }}">Open →</a></td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}<div class="empty"><p>No apps cached yet. Click <strong>Sync from AdMob</strong> to pull them from the API.</p></div>{% endif %}
{% endblock %}"""

TEMPLATE_FILES["app_detail.html"] = r"""{% extends "base.html" %}
{% block title %}{{ app.name }} · Flow{% endblock %}
{% block content %}
<section class="page-head">
  <p class="eyebrow"><a href="/apps">← Apps</a></p>
  <h1 class="display">{{ app.name or "(unnamed app)" }}</h1>
  <p class="mono small">{{ app.app_id }} · {{ app.platform }} · {{ app.package_name or "no store ID" }}</p>
</section>
<h2 class="section-title">Ad units</h2>
{% if ad_units %}
<table class="table">
  <thead><tr><th>Name</th><th>Format</th><th>Ad Unit ID</th></tr></thead>
  <tbody>
    {% for u in ad_units %}<tr><td>{{ u.name or "(unnamed)" }}</td><td><span class="pill">{{ u.ad_format }}</span></td><td class="mono small">{{ u.ad_unit_id }}</td></tr>{% endfor %}
  </tbody>
</table>
{% else %}<p class="empty">No ad units found for this app.</p>{% endif %}
{% endblock %}"""

TEMPLATE_FILES["mediation_list.html"] = r"""{% extends "base.html" %}
{% block title %}Mediation groups · Flow{% endblock %}
{% block content %}
<section class="page-head row-between">
  <div><p class="eyebrow">Mediation</p><h1 class="display">Your mediation groups</h1></div>
  <a href="/mediation/builder" class="btn-primary">+ Open Builder</a>
</section>
{% if groups %}
<table class="table">
  <thead><tr><th>Name</th><th>Source Ad Unit</th><th>Format</th><th>Platform</th><th>Countries</th><th>Source eCPM</th><th>Status</th><th>Updated</th><th></th></tr></thead>
  <tbody>
    {% for g in groups %}
    <tr>
      <td>{{ g.name }}</td>
      <td class="mono small">{{ g.target_ad_unit_id }}</td>
      <td><span class="pill">{{ g.ad_format }}</span></td>
      <td><span class="pill pill-{{ g.platform|lower }}">{{ g.platform }}</span></td>
      <td class="small">{% if g.country_mode == "GLOBAL" %}Global{% elif g.country_mode == "INCLUDE" %}+{{ g.countries|length }}{% else %}−{{ g.countries|length }}{% endif %}</td>
      <td class="small">${{ "%.2f"|format(g.base_avg_ecpm) }}</td>
      <td><span class="status status-{{ g.status|lower }}">{{ g.status }}</span></td>
      <td class="small">{{ g.updated_at.strftime("%Y-%m-%d %H:%M") }}</td>
      <td><a href="/mediation/{{ g.id }}">Open →</a></td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}<div class="empty"><p>No mediation groups yet. <a href="/mediation/builder">Open the Builder →</a></p></div>{% endif %}
{% endblock %}"""


TEMPLATE_FILES["mediation_builder.html"] = r"""{% extends "base.html" %}
{% block title %}Mediation Builder · Flow{% endblock %}
{% block content %}
<section class="page-head">
  <p class="eyebrow">Builder</p>
  <h1 class="display">Mediation builder</h1>
  <p class="lede">Pick an app and its ad units, choose who to target, and fetch live earnings. Flow then calculates the waterfall and builds it in AdMob for you.</p>
</section>

{% if not apps %}
<div class="empty">
  <p>You don't have any apps cached yet. Sync them first.</p>
  <form method="post" action="/apps/sync"><button class="btn-primary" type="submit">↻ Sync from AdMob</button></form>
</div>
{% else %}

<div class="builder-grid">
  <div>
    <div class="builder-step" id="account-step" style="display:none">
      <div class="builder-legend"><span class="num">00</span> AdMob Account</div>
      <input type="text" id="account-search" placeholder="Search accounts…" />
      <div id="account-list" class="country-chips" style="margin-top:8px"></div>
      <p class="muted small">Only the selected accounts' apps show up below.</p>
    </div>

    <div class="builder-step">
      <div class="builder-legend"><span class="num">01</span> Select App</div>
      <input type="text" id="app-search" placeholder="Search apps by name or ID…" style="margin-bottom:8px" />
      <select id="app-select">
        <option value="">— Choose an app —</option>
      </select>
    </div>

    <div class="builder-step" id="adunit-step" style="display:none">
      <div class="builder-legend"><span class="num">02</span> Select Source Ad Units</div>
      <div class="row-between" style="margin-bottom:10px">
        <input type="text" id="adunit-search" placeholder="Filter ad units…" />
        <div>
          <button type="button" class="btn-ghost btn-sm" id="adunit-all">Select all</button>
          <button type="button" class="btn-ghost btn-sm" id="adunit-none">Clear</button>
        </div>
      </div>
      <div id="adunit-list" class="adunit-cards"></div>
    </div>

    <div class="builder-step">
      <div class="builder-legend"><span class="num">03</span> Country Targeting</div>
      <div class="radio-row">
        <label><input type="radio" name="country_mode" value="GLOBAL" checked /> <span><b>Global</b> — target all countries</span></label>
        <label><input type="radio" name="country_mode" value="INCLUDE" /> <span><b>Choose</b> specific countries</span></label>
        <label><input type="radio" name="country_mode" value="EXCLUDE" /> <span><b>Exclude</b> specific countries</span></label>
      </div>
      <div id="country-picker" style="display:none">
        <input type="text" id="country-search" placeholder="Search countries…" />
        <div id="country-list" class="country-chips"></div>
        <p class="muted small">Or paste comma-separated ISO-2 codes:</p>
        <input type="text" id="country-paste" placeholder="US, GB, DE, JP" />
      </div>
    </div>

    <div class="builder-step">
      <div class="builder-legend"><span class="num">04</span> Waterfall &amp; Bidding</div>
      <div class="grid grid-2">
        <label><span class="lbl">Number of waterfall lines (1–{{ max_lines }})</span>
          <input type="number" id="line-count" min="1" max="{{ max_lines }}" value="{{ default_lines }}" /></label>
        <label><span class="lbl">Group name prefix</span>
          <input type="text" id="name-prefix" value="Global" /></label>
      </div>

      <div class="bidding-callout" id="bidding-callout">
        <div class="bidding-callout-head">
          <div>
            <strong>⚡ Include all bidding networks</strong>
            <p class="muted small" style="margin:4px 0 0">On: add every bidding network you've set up on <a href="/bidding">Bidding</a> for this app. Off: use AdMob Network only.</p>
          </div>
          <label class="bidding-toggle">
            <input type="checkbox" id="include-bidding" checked />
            <span class="bidding-slider"></span>
          </label>
        </div>
      </div>
    </div>

    <div class="report-source" style="margin:4px 0 14px">
      <span class="lbl" style="display:block;margin-bottom:6px">eCPM source</span>
      <div class="radio-row">
        <label><input type="radio" name="report_type" value="mediation" checked /> <span><b>Mediation</b> — Observed eCPM (matches AdMob UI · recommended)</span></label>
        <label><input type="radio" name="report_type" value="network" /> <span><b>Network</b> — AdMob Network only</span></label>
      </div>
    </div>

    <div class="form-actions">
      <button class="btn-primary" id="fetch-report-btn" disabled>📊 Fetch AdMob Report (Last 7 Days)</button>
      <a href="/mediation" class="btn-ghost">Cancel</a>
    </div>
  </div>

  <div>
    <div class="preview-panel" id="preview-panel">
      <p class="eyebrow">Live preview</p>
      <h3 class="section-title" style="margin-top:6px">Selected configuration</h3>
      <div id="preview-summary" class="muted">No app selected yet.</div>
    </div>
    <div class="preview-panel" id="selected-panel" style="margin-top:16px; display:none">
      <p class="eyebrow">Selected ad units (<span id="sel-count">0</span>)</p>
      <div id="selected-units"></div>
    </div>
  </div>
</div>

<!-- Full-screen blocker shown while a push runs: progress bar + count + message.
     position:fixed + high z-index so the user can't click anything else. -->
<div id="push-overlay" style="display:none">
  <div class="push-modal">
    <h3 class="push-title">Creating mediation groups…</h3>
    <div class="push-count"><span id="push-done">0</span> / <span id="push-total">0</span></div>
    <div class="push-bar"><div class="push-bar-fill" id="push-bar-fill"></div></div>
    <p class="push-msg" id="push-msg">Starting…</p>
    <p class="push-note">Please keep this tab open — this can take a minute.</p>
  </div>
</div>
<div id="snackbar"></div>

<section id="report-section" style="display:none">
  <h2 class="section-title">Ad Unit Reports</h2>
  <p class="muted small" id="report-date-range"></p>
  <div id="report-cards"></div>
  <div class="calc-explainer">
    <strong>Waterfall Formula:</strong> Each tier = <span class="mono">Base eCPM × Vx multiplier</span>. Base = 7-day average eCPM.
    <br>
    <span class="muted small mono">V1 × {{ tier_multipliers[0] }} (top) · V2 × {{ tier_multipliers[1] }} · V3 × {{ tier_multipliers[2] }} · V4 × {{ tier_multipliers[3] }} · V5 × {{ tier_multipliers[4] }} · V6 × {{ tier_multipliers[5] }} · V7 × {{ tier_multipliers[6] }} · V8 × {{ tier_multipliers[7] }} · V9 × {{ tier_multipliers[8] }} · V10 × {{ tier_multipliers[9] }} (bottom)</span>
    <br>
    <span class="muted small">Every tier value is clamped to <b>${{ min_ecpm }}</b> – <b>${{ max_ecpm|int }}</b>.</span>
  </div>
  <div class="form-actions">
    <button class="btn-primary btn-lg" id="push-btn">▶ Push to AdMob</button>
    <button class="btn-secondary btn-lg" id="generate-btn">Save as draft</button>
  </div>

  <hr style="margin: 32px 0; border: 0; border-top: 1px solid var(--line)" />

  <h3 class="section-title" style="margin-top: 0">Advanced: Push lines to an existing AdMob group</h3>
  <p class="muted small" style="margin: 6px 0 14px">
    For Mediation Pro user-value-segment groups. Uses the eCPMs from the first selected ad unit's tier table.
  </p>

  <div class="form-actions" style="margin-bottom: 14px">
    <button type="button" class="btn-secondary btn-sm" id="fetch-admob-groups-btn">↻ Load my AdMob groups</button>
  </div>

  <div id="admob-groups-list" style="display:none">
    <label><span class="lbl">Pick the target group</span>
      <select id="target-group-select">
        <option value="">— Choose an AdMob group —</option>
      </select>
    </label>
    <p class="muted small" id="target-group-info" style="margin: 6px 0"></p>
    <div class="form-actions">
      <button type="button" class="btn-primary btn-lg" id="push-existing-btn" disabled>▶ Patch lines into selected group</button>
    </div>
  </div>

</section>

{% endif %}

<script>
const APP_AD_UNITS = {{ ad_units_by_app|tojson }};
const COUNTRIES = {{ countries|tojson }};
const MAX_LINES = {{ max_lines }};
const DEFAULT_LINES = {{ default_lines }};
const EXISTING_GROUPS = {{ existing_groups|tojson }};
const ALL_APPS = {{ all_apps|tojson }};
const ACCOUNTS = {{ accounts|tojson }};

const $ = sel => document.querySelector(sel);
const $$ = sel => [...document.querySelectorAll(sel)];

const state = {
  app_id: null, app_label: "", platform: "",
  ad_units: [],
  country_mode: "GLOBAL",
  countries: new Set(),
  line_count: DEFAULT_LINES,
  floor_type: "ALL_PRICES",
  unique_names: true,
  include_bidding_networks: true,
  name_prefix: "Global",
  report_type: "mediation",
  report: null,
};

// eCPM source toggle (Mediation = matches AdMob UI / Network = AdMob Network only)
$$('input[name="report_type"]').forEach(r => r.addEventListener("change", () => {
  state.report_type = document.querySelector('input[name="report_type"]:checked').value;
}));

// Wire the "Include All Bidding Networks" toggle (default ON).
const __incBidCb = document.getElementById("include-bidding");
if (__incBidCb) {
  __incBidCb.addEventListener("change", e => {
    state.include_bidding_networks = e.target.checked;
    const callout = document.getElementById("bidding-callout");
    if (callout) callout.classList.toggle("is-on", e.target.checked);
  });
  // Initial visual state
  const callout = document.getElementById("bidding-callout");
  if (callout) callout.classList.toggle("is-on", __incBidCb.checked);
}

function renderSelectedUnits() {
  const panel = $("#selected-panel"), wrap = $("#selected-units"), countEl = $("#sel-count");
  if (!panel || !wrap) return;
  const units = state.ad_units || [];
  if (countEl) countEl.textContent = units.length;
  if (!units.length) { panel.style.display = "none"; wrap.innerHTML = ""; return; }
  panel.style.display = "";
  wrap.innerHTML = units.map(u => `
    <div class="sel-unit">
      <div class="sel-unit-info">
        <div class="sel-unit-name">${u.name || "(unnamed)"} <span class="pill">${u.ad_format}</span></div>
        <div class="mono small muted">${u.ad_unit_id}</div>
      </div>
      <button type="button" class="sel-unit-remove" data-id="${u.id}" title="Remove">✕</button>
    </div>`).join("");
  wrap.querySelectorAll(".sel-unit-remove").forEach(b => {
    b.addEventListener("click", () => {
      state.ad_units = state.ad_units.filter(s => String(s.id) !== String(b.dataset.id));
      renderAdUnits(); updatePreview();
    });
  });
}

function updatePreview() {
  renderSelectedUnits();   // keep the "Selected ad units" list in sync
  const el = $("#preview-summary");
  if (!state.app_id) { el.innerHTML = '<span class="muted">No app selected yet.</span>'; return; }
  const lines = [];
  lines.push(`<div class="kv"><span>App</span><b>${state.app_label || ""}</b></div>`);
  lines.push(`<div class="kv"><span>Source ad units</span><b>${state.ad_units.length}</b></div>`);
  let c;
  if (state.country_mode === "GLOBAL") c = "Global";
  else if (state.countries.size === 0) c = `${state.country_mode === "INCLUDE" ? "Choose" : "Exclude"} (none)`;
  else c = `${state.country_mode === "INCLUDE" ? "+" : "−"}${state.countries.size}: ${[...state.countries].join(", ")}`;
  lines.push(`<div class="kv"><span>Countries</span><b>${c}</b></div>`);
  lines.push(`<div class="kv"><span>Tiers per ad unit</span><b>${state.line_count}</b></div>`);
  lines.push(`<div class="kv"><span>Bidding</span><b>${state.include_bidding_networks ? "AdMob Network + replicated third-party" : "AdMob Network only (default)"}</b></div>`);
  const totalAdUnits = state.ad_units.length * state.line_count;
  lines.push(`<div class="kv"><span>Will create</span><b>${totalAdUnits} tier ad unit(s) + ${state.ad_units.length} mediation group(s)</b></div>`);
  lines.push(`<div class="kv"><span>Group targeting</span><b>source + ${state.line_count} tier ad units each</b></div>`);
  el.innerHTML = lines.join("");
  const btn = $("#fetch-report-btn");
  if (btn) btn.disabled = !(state.app_id && state.ad_units.length > 0);
}

function renderAdUnits() {
  const list = APP_AD_UNITS[state.app_id] || [];
  const wrap = $("#adunit-list");
  const filter = ($("#adunit-search").value || "").toLowerCase();
  wrap.innerHTML = "";
  const filtered = list.filter(u => !filter || (u.name||"").toLowerCase().includes(filter) || u.ad_unit_id.toLowerCase().includes(filter) || (u.ad_format||"").toLowerCase().includes(filter));
  if (!filtered.length) { wrap.innerHTML = '<p class="muted small">No ad units match.</p>'; return; }
  filtered.forEach(u => {
    const sel = state.ad_units.some(s => s.id === u.id);
    const card = document.createElement("div");
    card.className = "adunit-card" + (sel ? " is-selected" : "");
    const existing = EXISTING_GROUPS[u.ad_unit_id] || [];
    const existingInfo = existing.length
      ? `<div class="small muted" style="margin-top:6px">${existing.length} existing group(s): ` +
        existing.slice(0, 3).map(g => `<a href="/mediation/${g.id}" target="_blank">${g.name}</a>` + (g.admob_group_id ? ` <span class="pill pill-good">in AdMob</span>` : "")).join(", ") +
        (existing.length > 3 ? `, +${existing.length - 3} more` : "") +
        `</div>`
      : "";
    card.innerHTML = `<div><div class="adunit-name">${u.name || "(unnamed)"} <span class="pill">${u.ad_format}</span></div><div class="adunit-id mono small">${u.ad_unit_id}</div>${existingInfo}</div><button type="button" class="btn-ghost btn-sm">${sel ? "Selected ✓" : "Select"}</button>`;
    // Whole card is clickable to toggle selection (not just the button).
    // Skip when the user clicked an existing-group link inside the card.
    card.addEventListener("click", (e) => {
      if (e.target.closest("a")) return;
      if (sel) state.ad_units = state.ad_units.filter(s => s.id !== u.id);
      else state.ad_units.push(u);
      renderAdUnits(); updatePreview();
    });
    wrap.appendChild(card);
  });
}

function renderCountries() {
  const filter = ($("#country-search").value || "").toLowerCase();
  const wrap = $("#country-list");
  wrap.innerHTML = "";
  COUNTRIES.filter(c => !filter || c.name.toLowerCase().includes(filter) || c.code.toLowerCase().includes(filter)).forEach(c => {
    const on = state.countries.has(c.code);
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "country-chip" + (on ? " is-selected" : "");
    chip.textContent = `${c.code} · ${c.name}`;
    chip.addEventListener("click", () => {
      if (on) state.countries.delete(c.code); else state.countries.add(c.code);
      updateAutoPrefix(); renderCountries(); updatePreview();
    });
    wrap.appendChild(chip);
  });
}

// ---- AdMob account selector + per-account app filtering (with search) ----
let selectedAccounts = new Set();
(function initAccounts(){
  try { (JSON.parse(localStorage.getItem("selectedPublishers")||"[]")||[]).forEach(p=>selectedAccounts.add(p)); } catch(e){}
  const valid = new Set(ACCOUNTS.map(a=>a.publisher));
  selectedAccounts = new Set([...selectedAccounts].filter(p=>valid.has(p)));
  if (selectedAccounts.size===0) ACCOUNTS.forEach(a=>selectedAccounts.add(a.publisher)); // default: all
})();
function saveAccounts(){ try{ localStorage.setItem("selectedPublishers", JSON.stringify([...selectedAccounts])); }catch(e){} }

function renderAccounts(){
  const step = document.getElementById("account-step");
  if (step) step.style.display = (ACCOUNTS.length > 1) ? "" : "none";
  const wrap = $("#account-list"); if (!wrap) return;
  const f = ($("#account-search").value||"").toLowerCase();
  wrap.innerHTML = "";
  ACCOUNTS.filter(a => !f || a.publisher.toLowerCase().includes(f)).forEach(a => {
    const on = selectedAccounts.has(a.publisher);
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "country-chip" + (on ? " is-selected" : "");
    chip.textContent = `${a.publisher} (${a.app_count})`;
    chip.addEventListener("click", () => {
      if (on) selectedAccounts.delete(a.publisher); else selectedAccounts.add(a.publisher);
      if (selectedAccounts.size===0) ACCOUNTS.forEach(x=>selectedAccounts.add(x.publisher)); // never empty
      saveAccounts(); renderAccounts(); renderAppOptions();
    });
    wrap.appendChild(chip);
  });
}

function renderAppOptions(){
  const sel = $("#app-select"); if (!sel) return;
  const f = ($("#app-search").value||"").toLowerCase();
  const prev = state.app_id;
  sel.innerHTML = '<option value="">— Choose an app —</option>';
  ALL_APPS
    .filter(a => selectedAccounts.has(a.publisher))
    .filter(a => !f || (a.name||"").toLowerCase().includes(f) || (a.app_id||"").toLowerCase().includes(f))
    .forEach(a => {
      const o = document.createElement("option");
      o.value = a.id; o.dataset.platform = a.platform;
      o.textContent = `${a.name || a.app_id} · ${a.platform} · ${a.app_id}`;
      if (prev && String(a.id) === String(prev)) o.selected = true;
      sel.appendChild(o);
    });
  // If the previously-chosen app is now hidden (account/search changed), reset.
  const stillVisible = ALL_APPS.some(a => String(a.id)===String(prev) && selectedAccounts.has(a.publisher));
  if (prev && !stillVisible){
    state.app_id=null; state.app_label=""; state.platform=""; state.ad_units=[];
    const astep = $("#adunit-step"); if (astep) astep.style.display="none";
    updatePreview();
  }
}

(function(){
  const as = $("#account-search"); if (as) as.addEventListener("input", renderAccounts);
  const aps = $("#app-search"); if (aps) aps.addEventListener("input", renderAppOptions);
  renderAccounts(); renderAppOptions();
})();

$("#app-select").addEventListener("change", e => {
  state.app_id = e.target.value || null;
  const opt = e.target.options[e.target.selectedIndex];
  state.app_label = opt.textContent;
  state.platform = (opt.dataset.platform || "").toUpperCase();
  state.ad_units = [];
  $("#adunit-step").style.display = state.app_id ? "" : "none";
  if (state.app_id) renderAdUnits();
  updatePreview();
});
$("#adunit-search").addEventListener("input", renderAdUnits);
$("#adunit-all").addEventListener("click", () => { state.ad_units = [...(APP_AD_UNITS[state.app_id] || [])]; renderAdUnits(); updatePreview(); });
$("#adunit-none").addEventListener("click", () => { state.ad_units = []; renderAdUnits(); updatePreview(); });
// When countries are chosen, auto-fill the group name prefix (US, US_GB, ...)
// so the user doesn't type it by hand. Manual edits afterwards still stick
// until the country selection changes again.
function updateAutoPrefix() {
  let p;
  if (state.country_mode === "GLOBAL" || state.countries.size === 0) p = "Global";
  else p = [...state.countries].slice(0, 4).join("_") + (state.countries.size > 4 ? "_etc" : "");
  const inp = $("#name-prefix");
  if (inp) inp.value = p;
  state.name_prefix = p;
}
$$('input[name="country_mode"]').forEach(r => r.addEventListener("change", () => {
  const mode = document.querySelector('input[name="country_mode"]:checked').value;
  state.country_mode = mode;
  $("#country-picker").style.display = mode === "GLOBAL" ? "none" : "";
  if (mode === "GLOBAL") state.countries.clear();
  if (mode !== "GLOBAL") renderCountries();
  updateAutoPrefix(); updatePreview();
}));
$("#country-search").addEventListener("input", renderCountries);
$("#country-paste").addEventListener("change", e => {
  e.target.value.split(",").map(s => s.trim().toUpperCase()).filter(Boolean).forEach(c => state.countries.add(c));
  updateAutoPrefix(); renderCountries(); updatePreview();
});
$("#line-count").addEventListener("change", e => { state.line_count = Math.max(1, Math.min(MAX_LINES, +e.target.value || DEFAULT_LINES)); updatePreview(); if (state.report) renderReport(); });
$("#name-prefix").addEventListener("input", e => { state.name_prefix = e.target.value || "Group"; updatePreview(); });

$("#fetch-report-btn").addEventListener("click", async () => {
  const btn = $("#fetch-report-btn");
  btn.disabled = true; btn.textContent = "Fetching report…";
  try {
    const ad_unit_ids = state.ad_units.map(u => u.ad_unit_id);
    const res = await fetch("/mediation/builder/fetch-report", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        ad_unit_ids,
        country_mode: state.country_mode,
        countries: [...state.countries],
        report_type: state.report_type,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Fetch failed");
    state.report = data.report || {};
    const geo = (data.countries && data.countries.length)
      ? `Geo: ${data.countries.join(", ")}` : "Geo: Global (all countries)";
    const src = (data.report_type === "network")
      ? "Source: Network (AdMob Network)" : "Source: Mediation (Observed eCPM)";
    $("#report-date-range").textContent = `Date range: ${data.start} → ${data.end} (last 7 days) · ${geo} · ${src}`;
    renderReport();
    $("#report-section").style.display = "";
    $("#report-section").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    alert("Error fetching report: " + err.message);
  } finally {
    btn.disabled = false; btn.textContent = "📊 Fetch AdMob Report (Last 7 Days)";
  }
});

function fmtPct(n) { return (n * 100).toFixed(2) + "%"; }
function fmtUSD(n) { return "$" + (n || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
const TIER_MULTIPLIERS = {{ tier_multipliers|tojson }};
const MIN_ECPM = {{ min_ecpm }};
const MAX_ECPM = {{ max_ecpm }};

function computeLines(avg, count) {
  // V1 = highest (top), VN = lowest (bottom). Pick first `count` multipliers.
  // Each tier = base × Vx multiplier, clamped to [MIN_ECPM, MAX_ECPM].
  //
  // Low-eCPM handling: if the real average is BELOW the floor (MIN_ECPM), the
  // raw multipliers would push almost every tier under the floor and clamp them
  // all to the same value (e.g. base $0.06 -> V3..V10 all $0.20, no spread).
  // Instead, use the floor itself as the base so the tiers still get a proper
  // spread (V1 $1.10 ... down), and the bottom tier lands on exactly the floor.
  const base = Math.max(avg, MIN_ECPM);
  return TIER_MULTIPLIERS.slice(0, Math.min(count, TIER_MULTIPLIERS.length))
    .map(m => {
      const v = base * m;
      return +Math.min(MAX_ECPM, Math.max(MIN_ECPM, v)).toFixed(2);
    });
}

function renderReport() {
  const wrap = $("#report-cards");
  wrap.innerHTML = "";
  state.ad_units.forEach(u => {
    const m = (state.report || {})[u.ad_unit_id] || {};
    const ecpm = m.ecpm_usd || 0;
    const lines = computeLines(ecpm, state.line_count);

    const card = document.createElement("div");
    card.className = "report-card";
    const planNote = `<div class="muted small" style="margin-top:8px">Will create <b>1</b> mediation group targeting this ad unit: <b>waterfall MANUAL lines</b> from your saved 3rd-party networks (one per network, at the computed tier eCPMs) + an <b>AdMob Network LIVE bidding line</b>. Save network credentials on the <b>/networks</b> page first — each saved network becomes one waterfall line.</div>`;

    card.innerHTML = `
      <div class="report-card-head">
        <div><div class="report-card-title">${u.name || "(unnamed)"}</div><div class="mono small muted">${u.ad_unit_id} · ${u.ad_format}</div></div>
        <div class="report-card-summary">Avg eCPM <b>${fmtUSD(ecpm)}</b> · Revenue <b>${fmtUSD(m.revenue_usd)}</b></div>
      </div>
      <div class="metric-grid">
        <div class="metric"><span class="metric-label">Avg eCPM</span><span class="metric-value">${fmtUSD(ecpm)}</span></div>
        <div class="metric"><span class="metric-label">Revenue</span><span class="metric-value good">${fmtUSD(m.revenue_usd)}</span></div>
        <div class="metric"><span class="metric-label">Match Rate</span><span class="metric-value">${fmtPct(m.match_rate || 0)}</span></div>
        <div class="metric"><span class="metric-label">Show Rate</span><span class="metric-value">${fmtPct(m.show_rate || 0)}</span></div>
        <div class="metric"><span class="metric-label">Fill Rate</span><span class="metric-value">${fmtPct(m.fill_rate || 0)}</span></div>
        <div class="metric"><span class="metric-label">RPM</span><span class="metric-value">${fmtUSD(m.rpm_usd)}</span></div>
        <div class="metric"><span class="metric-label">Requests</span><span class="metric-value">${(m.ad_requests||0).toLocaleString()}</span></div>
        <div class="metric"><span class="metric-label">Impressions</span><span class="metric-value">${(m.impressions||0).toLocaleString()}</span></div>
      </div>
      ${planNote}
      <div class="line-table">
        <div class="line-table-head"><div>Tier</div><div>eCPM (editable)</div><div>Source</div></div>
        ${lines.map((v, i) => `
          <div class="line-table-row">
            <div class="mono small">${i+1}</div>
            <input type="number" min="0" step="0.01" value="${v.toFixed(2)}" data-au="${u.ad_unit_id}" data-i="${i}" class="line-input" />
            <div class="small muted">AdMob Network (MANUAL)</div>
          </div>
        `).join("")}
      </div>
    `;
    wrap.appendChild(card);
  });
}

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function showSnackbar(text) {
  const sb = document.getElementById("snackbar");
  if (!sb) return;
  sb.textContent = text; sb.classList.add("show");
  clearTimeout(sb._t); sb._t = setTimeout(() => sb.classList.remove("show"), 4000);
}
function showPushOverlay(on) {
  const o = document.getElementById("push-overlay");
  if (o) o.style.display = on ? "flex" : "none";
}
function updatePushProgress(done, total, msg) {
  done = done || 0; total = total || 0;
  const pct = total ? Math.round(done / total * 100) : 0;
  const f = document.getElementById("push-bar-fill"); if (f) f.style.width = pct + "%";
  const d = document.getElementById("push-done"); if (d) d.textContent = done;
  const t = document.getElementById("push-total"); if (t) t.textContent = total;
  const m = document.getElementById("push-msg"); if (m && msg) m.textContent = msg;
}

// Poll a background push job. Each request is short, so the ~100s proxy limit
// never triggers no matter how long the actual AdMob push takes. Each poll
// updates the progress bar + count + snackbar.
async function pollPushJob(jobId) {
  let lastDone = -1;
  for (let i = 0; i < 300; i++) {            // ~12 min ceiling at 2.5s each
    await _sleep(2500);
    let r;
    try { r = await fetch(`/mediation/builder/push-status/${jobId}`); }
    catch (_) { continue; }                  // transient blip — keep polling
    if (r.status === 404)
      throw new Error("Push job not found — open the Mediation page to see if the groups were created.");
    let j; try { j = JSON.parse(await r.text()); } catch (_) { continue; }
    if (j.status === "running") {
      updatePushProgress(j.done, j.total, j.message);
      if (typeof j.done === "number" && j.done !== lastDone && j.total) {
        lastDone = j.done;
        showSnackbar(`${j.done}/${j.total} ad unit(s) created in the background…`);
      }
    }
    if (j.status === "done") { updatePushProgress(j.total, j.total, "Done ✓"); return j.result; }
    if (j.status === "error") throw new Error(j.error || "Push failed");
  }
  throw new Error("Push is taking unusually long. Open the Mediation page to check the created groups.");
}

async function submitGroups(endpoint, label) {
    const btn = document.getElementById(label === "push" ? "push-btn" : "generate-btn");
    const items = state.ad_units.map(u => {
      const lineInputs = $$(`.line-input[data-au="${u.ad_unit_id}"]`);
      const lines = lineInputs.map(inp => +inp.value || 0);
      return {
        ad_unit_id: u.ad_unit_id, ad_unit_name: u.name, ad_format: u.ad_format,
        metrics: (state.report || {})[u.ad_unit_id] || {},
        lines,
      };
    });

    if (label === "push") {
      const totalLines = items.reduce((s, it) => s + it.lines.filter(l => l > 0).length, 0);
      const summary = `Pre-flight check:\n\n` +
        `• ${items.length} source ad unit(s) selected\n` +
        `• ${totalLines} waterfall tier eCPM(s) computed\n\n` +
        `Will create (via AdMob API), per source ad unit:\n` +
        `• 1 mediation group targeting that ad unit\n` +
        `• Waterfall MANUAL lines — one per 3rd-party network you saved\n` +
        `  on /networks, at the computed tier eCPMs\n` +
        `• 1 AdMob Network LIVE bidding line\n\n` +
        `If you have not saved any 3rd-party network credentials on the\n` +
        `/networks page, the group is still created but with 0 waterfall\n` +
        `lines (only the AdMob Network bidding line).\n\n` +
        `Continue?`;
      if (!confirm(summary)) return;
    }

    const body = {
      app_id: state.app_id, country_mode: state.country_mode,
      countries: [...state.countries], floor_type: state.floor_type,
      unique_names: state.unique_names, name_prefix: state.name_prefix,
      include_bidding_networks: state.include_bidding_networks,
      items,
    };
    btn.disabled = true; const orig = btn.textContent; btn.textContent = "Working...";
    try {
      const res = await fetch(endpoint, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body),
      });
      // The push can be long (many AdMob calls). If it exceeds the proxy's
      // ~100s limit, the server/proxy returns an HTML error page, not JSON —
      // parse defensively so we show a clear message instead of a cryptic
      // "Unexpected token '<'".
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); }
      catch (_) {
        throw new Error(
          "The request took too long and the connection timed out.\n\n" +
          "IMPORTANT: your group(s) may STILL have been created on AdMob — " +
          "open the Mediation page to check BEFORE retrying (so you don't make duplicates).");
      }
      if (!res.ok) throw new Error(data.detail || "Request failed");

      // Push runs as a background job — poll until it finishes, with a
      // blocking overlay + progress bar + snackbar so the user can't touch
      // anything mid-run. (Save/draft returns directly, no job_id to poll.)
      if (data.job_id) {
        btn.textContent = "Working…";
        showPushOverlay(true);
        updatePushProgress(0, items.length, "Starting…");
        showSnackbar(`Creating ${items.length} mediation group(s) in the background…`);
        try {
          data = await pollPushJob(data.job_id);
        } finally {
          showPushOverlay(false);
        }
      }

      let msg;
      if (label === "push") {
        const groups = data.groups || [];
        const ok = groups.filter(g => g.status === "PUSHED").length;
        const partial = groups.filter(g => g.status === "PUSHED_PARTIAL").length;
        const failed = groups.filter(g => g.status === "PUSH_FAILED").length;
        const inAdMob = ok + partial;
        msg = `═══ PUSH RESULT ═══\n\n`;
        const okCount = groups.filter(g => g.status === "PUSHED").length;
        const partialCount = groups.filter(g => g.status === "PUSHED_PARTIAL").length;
        const failCount = groups.filter(g => g.status === "PUSH_FAILED").length;
        msg += `Mediation groups in AdMob: ${okCount}/${groups.length}`;
        if (partialCount) msg += ` (${partialCount} partial)`;
        msg += `\n`;
        if (failCount) msg += `✗ Failed entirely: ${failCount}\n`;
        msg += `\n`;
        groups.slice(0, 20).forEach(g => {
          const mark = g.status === "PUSHED" ? "✓"
                     : g.status === "PUSHED_PARTIAL" ? "⚠" : "✗";
          msg += `${mark} ${g.name}\n`;
          msg += `   source ad unit: ${g.source_ad_unit_id}\n`;
          if (g.admob_group_id)
            msg += `   AdMob mediation group id: ${g.admob_group_id}\n`;
          msg += `   Waterfall lines in group: ${g.waterfall_lines_actual ?? 0}`;
          const nets = g.waterfall_networks || [];
          if (nets.length) msg += `  (${nets.join(", ")})`;
          msg += `\n`;
          msg += `   Bidding line (AdMob Network): ${g.bidding_lines_actual ?? 0}\n`;
          const tiers = g.waterfall_tier_ecpms || [];
          if (tiers.length) {
            msg += `   Computed tier eCPMs: ` +
                   tiers.map(e => `$${Number(e).toFixed(2)}`).join(", ") + `\n`;
          }
          if ((g.waterfall_lines_actual ?? 0) === 0) {
            msg += `   ⚠ 0 waterfall lines — save 3rd-party network creds on /networks\n`;
          }
          msg += `\n`;
        });
        if (groups.length > 20) msg += `\n…and ${groups.length - 20} more (see /mediation)\n`;

        if ((data.push_errors || []).length) {
          msg += `\n═══ ERRORS ═══\n`;
          data.push_errors.slice(0, 15).forEach((e, i) => {
            const tierInfo = e.tier ? ` (tier ${e.tier})` : "";
            const stageInfo = e.stage ? ` at ${e.stage}` : "";
            msg += `\n${i+1}. ad unit ${e.ad_unit_id}${tierInfo}${stageInfo}:\n   ${e.error}\n`;
          });
          if (data.push_errors.length > 15) msg += `\n…and ${data.push_errors.length - 15} more errors\n`;
          const allErrs = data.push_errors.map(e => (e.error || "").toLowerCase()).join(" ");
          if (allErrs.includes("permission") || allErrs.includes("403")) {
            msg += `\n═══ HINT ═══\nAdMob Write API may not be enabled. Contact your AdMob account manager.`;
          } else if (allErrs.includes("exhausted") || allErrs.includes("quota")) {
            msg += `\n═══ HINT ═══\nQuota exhausted. Wait 60s and retry with fewer tiers / ad units.`;
          }
        }
      } else {
        msg = `Saved ${data.groups.length} draft group(s) locally (not pushed to AdMob).`;
      }
      // Stay on the Builder so the same app + ad units remain selected. This
      // lets the user create another country-level group for the SAME app
      // without re-selecting everything: just change the country above,
      // Fetch Report again (now geo-scoped), and push.
      msg += `\n\n────────────────────\n` +
             `You're still on the Builder — your app & ad units stay selected.\n` +
             `To make another country's group for this app: change the country\n` +
             `above → Fetch Report again → push. Open /mediation to view all groups.`;
      alert(msg);
      btn.disabled = false; btn.textContent = orig;
    } catch (err) {
      alert("Error: " + err.message);
      btn.disabled = false; btn.textContent = orig;
    }
}

document.getElementById("push-btn").addEventListener("click", () => submitGroups("/mediation/builder/push-to-admob", "push"));
document.getElementById("generate-btn").addEventListener("click", () => submitGroups("/mediation/builder/generate", "save"));

let LOADED_ADMOB_GROUPS = [];

document.getElementById("fetch-admob-groups-btn").addEventListener("click", async () => {
  const btn = document.getElementById("fetch-admob-groups-btn");
  btn.disabled = true; const orig = btn.textContent; btn.textContent = "Loading…";
  try {
    const res = await fetch("/mediation/builder/fetch-admob-groups", {method: "POST"});
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to load groups");
    LOADED_ADMOB_GROUPS = data.groups || [];
    const sel = document.getElementById("target-group-select");
    sel.innerHTML = '<option value="">— Choose an AdMob group —</option>';
    LOADED_ADMOB_GROUPS.forEach(g => {
      const opt = document.createElement("option");
      opt.value = g.mediation_group_id;
      opt.textContent = `${g.display_name || g.mediation_group_id} · ${g.platform || "?"} · ${g.format || "?"} · ${g.line_count} line(s) · ${g.state}`;
      sel.appendChild(opt);
    });
    document.getElementById("admob-groups-list").style.display = "";
    if (!LOADED_ADMOB_GROUPS.length) {
      document.getElementById("target-group-info").innerHTML = "<em>No groups returned.</em>";
    }
  } catch (err) {
    alert("Error loading AdMob groups: " + err.message);
  } finally {
    btn.disabled = false; btn.textContent = orig;
  }
});

document.getElementById("target-group-select").addEventListener("change", e => {
  const id = e.target.value;
  const pushBtn = document.getElementById("push-existing-btn");
  const info = document.getElementById("target-group-info");
  if (!id) { pushBtn.disabled = true; info.textContent = ""; return; }
  const g = LOADED_ADMOB_GROUPS.find(x => x.mediation_group_id === id);
  if (!g) { pushBtn.disabled = true; return; }
  pushBtn.disabled = false;
  info.innerHTML = `Currently has <b>${g.line_count}</b> line(s). Targets: ${(g.ad_unit_ids || []).map(x => `<code>${x}</code>`).join(", ") || "(none)"}.`;
});

document.getElementById("push-existing-btn").addEventListener("click", async () => {
  const sel = document.getElementById("target-group-select");
  const groupId = sel.value;
  if (!groupId) { alert("Pick a group first."); return; }
  const g = LOADED_ADMOB_GROUPS.find(x => x.mediation_group_id === groupId);
  if (!state.ad_units.length || !state.report) {
    alert("Select an ad unit and fetch the AdMob report first.");
    return;
  }
  const firstAu = state.ad_units[0];
  const inputs = $$(`.line-input[data-au="${firstAu.ad_unit_id}"]`);
  const ecpms = inputs.map(i => +i.value || 0).filter(v => v > 0);
  if (!ecpms.length) { alert("No positive eCPMs to push."); return; }
  if (!confirm(`Patch ${ecpms.length} line(s) into AdMob group "${g.display_name}"?`)) return;

  const btn = document.getElementById("push-existing-btn");
  btn.disabled = true; const orig = btn.textContent; btn.textContent = "Patching…";
  try {
    const res = await fetch("/mediation/builder/push-to-existing", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        mediation_group_id: groupId,
        ecpms,
        group_display_name: g.display_name || groupId,
      }),
    });
    const data = await res.json();
    if (data.status === "failed") {
      alert(`Failed to patch group.\n\nError: ${data.error}`);
    } else {
      const msg = data.status === "ok"
        ? `✓ Patched ${data.lines_pushed} of ${data.lines_requested} lines.`
        : `⚠ Partial: patched ${data.lines_pushed} of ${data.lines_requested} lines.`;
      alert(msg + "\n\nYou're still on the Builder. Open /mediation to view all groups.");
    }
  } catch (err) {
    alert("Error: " + err.message);
  } finally {
    btn.disabled = false; btn.textContent = orig;
  }
});

updatePreview();
</script>
{% endblock %}"""

TEMPLATE_FILES["mediation_detail.html"] = r"""{% extends "base.html" %}
{% block title %}{{ group.name }} · Flow{% endblock %}
{% block content %}
<section class="page-head row-between">
  <div>
    <p class="eyebrow"><a href="/mediation">← Mediation</a></p>
    <h1 class="display">{{ group.name }}</h1>
    <p class="mono small">{{ group.ad_format }} · {{ group.platform }} ·
      {% if group.country_mode == "GLOBAL" %}global
      {% elif group.country_mode == "INCLUDE" %}include {{ group.countries|join(", ") }}
      {% else %}exclude {{ group.countries|join(", ") }}{% endif %}
      · floor: {{ group.floor_type.replace("_"," ").title() }}
      · ad unit: <code>{{ group.target_ad_unit_id }}</code>
      {% if group.admob_group_id %}· <strong style="color:var(--good)">AdMob group ID: <code>{{ group.admob_group_id }}</code></strong>{% endif %}
    </p>
  </div>
  <div class="actions-col">
    <span class="status status-{{ group.status|lower }}">{{ group.status }}</span>
    <a href="/mediation/{{ group.id }}/export.json" class="btn-secondary" target="_blank">Export JSON</a>
    <form method="post" action="/mediation/{{ group.id }}/delete" onsubmit="return confirm('Delete this group?');"><button type="submit" class="btn-danger">Delete</button></form>
  </div>
</section>
<h2 class="section-title">Report snapshot</h2>
{% if group.report_metrics %}
<div class="metric-grid">
  <div class="metric"><span class="metric-label">Source Avg eCPM</span><span class="metric-value">${{ "%.2f"|format(group.report_metrics.get("ecpm_usd", 0)) }}</span></div>
  <div class="metric"><span class="metric-label">Revenue</span><span class="metric-value good">${{ "%.2f"|format(group.report_metrics.get("revenue_usd", 0)) }}</span></div>
  <div class="metric"><span class="metric-label">Match Rate</span><span class="metric-value">{{ "%.2f"|format((group.report_metrics.get("match_rate", 0))*100) }}%</span></div>
  <div class="metric"><span class="metric-label">Show Rate</span><span class="metric-value">{{ "%.2f"|format((group.report_metrics.get("show_rate", 0))*100) }}%</span></div>
  <div class="metric"><span class="metric-label">Fill Rate</span><span class="metric-value">{{ "%.2f"|format((group.report_metrics.get("fill_rate", 0))*100) }}%</span></div>
  <div class="metric"><span class="metric-label">RPM</span><span class="metric-value">${{ "%.2f"|format(group.report_metrics.get("rpm_usd", 0)) }}</span></div>
  <div class="metric"><span class="metric-label">Requests</span><span class="metric-value">{{ "{:,}".format(group.report_metrics.get("ad_requests", 0)) }}</span></div>
  <div class="metric"><span class="metric-label">Impressions</span><span class="metric-value">{{ "{:,}".format(group.report_metrics.get("impressions", 0)) }}</span></div>
</div>
{% else %}<p class="muted">No report snapshot saved.</p>{% endif %}
<h2 class="section-title">Waterfall lines</h2>
{% if group.waterfall_lines %}
<table class="table">
  <thead><tr><th>Tier</th><th>Line name</th><th>eCPM</th><th>Source</th><th>Mode</th><th>Tier ad unit ID</th><th>Enabled</th></tr></thead>
  <tbody>{% for line in group.waterfall_lines %}<tr><td>{{ line.priority + 1 }}</td><td>{{ line.line_name }}</td><td class="mono">${{ "%.2f"|format(line.ecpm_usd) }}</td><td>{{ line.network_code or "ADMOB" }}</td><td>{{ line.cpm_mode }}</td><td class="mono small">{{ line.admob_line_key or "—" }}</td><td>{{ "yes" if line.enabled else "no" }}</td></tr>{% endfor %}</tbody>
</table>
{% else %}<p class="muted">No waterfall lines.</p>{% endif %}
<div class="callout">
  <strong>Group structure:</strong> targets source ad unit + N tier ad units. Waterfall has N MANUAL AdMob Network lines (one per tier eCPM). Bidding has AdMob Network LIVE plus one LIVE line per replicated 3P network.
</div>
{% if group.last_push_response %}
<h2 class="section-title">Last push response (forensics)</h2>
<pre class="forensic-block">{{ group.last_push_response }}</pre>
{% endif %}
{% endblock %}"""

TEMPLATE_FILES["networks.html"] = r"""{% extends "base.html" %}
{% block title %}Networks · Flow{% endblock %}
{% block content %}
<section class="page-head">
  <p class="eyebrow">3rd-party networks</p>
  <h1 class="display">Network credentials</h1>
  <p class="lede">Save your ad network keys and IDs for each app. Everything is stored encrypted.</p>
</section>

{% if not apps %}
<div class="empty">
  <p>No apps cached yet. <form method="post" action="/apps/sync" style="display:inline"><button class="btn-primary" type="submit">↻ Sync from AdMob</button></form></p>
</div>
{% else %}

<div class="networks-page">
  <aside class="net-app-list">
    <h3>Apps</h3>
    {% for a in apps %}
      <a href="#app-{{ a.id }}" class="net-app-link">{{ a.name or a.app_id }}<br><span class="small mono muted">{{ a.platform }}</span></a>
    {% endfor %}
  </aside>

  <div class="net-app-content">
    {% for a in apps %}
    <section id="app-{{ a.id }}" class="net-app-section">
      <h2 class="section-title">{{ a.name or "(unnamed app)" }} <span class="pill pill-{{ a.platform|lower }}">{{ a.platform }}</span></h2>
      <p class="mono small muted">{{ a.app_id }}</p>

      <div class="net-tabs">
        {% for net in networks %}
          <button type="button" class="net-tab {% if loop.first %}is-active{% endif %}" data-tab="net-{{ a.id }}-{{ net.code }}">{{ net.name }}</button>
        {% endfor %}
      </div>

      {% for net in networks %}
      <div class="net-tab-content {% if loop.first %}is-active{% endif %}" id="net-{{ a.id }}-{{ net.code }}">
        <form method="post" action="/networks/{{ a.id }}/{{ net.code }}/save-app" class="net-form">
          <h4>App-level credentials</h4>
          {% if net.app_fields %}
            {% set app_creds = app_creds_by_app_net.get((a.id, net.code), {}) %}
            <div class="grid grid-2">
              {% for f in net.app_fields %}
                <label><span class="lbl">{{ f.label }}</span>
                  <input name="{{ f.key }}" type="{{ f.type }}" value="{{ app_creds.get(f.key, '') }}" placeholder="{{ f.help }}" />
                </label>
              {% endfor %}
            </div>
            <button class="btn-secondary btn-sm" type="submit">Save app credentials</button>
          {% else %}
            <p class="muted small">No app-level credentials needed for {{ net.name }}.</p>
          {% endif %}
        </form>

        <h4 style="margin-top:24px">Per ad unit ({{ a.ad_units|length }})</h4>
        {% if a.ad_units %}
          {% for u in a.ad_units %}
            {% set mapping = unit_creds_by_key.get((a.id, u.ad_unit_id, net.code), {}) %}
            <form method="post" action="/networks/{{ a.id }}/{{ net.code }}/save-unit/{{ u.ad_unit_id|urlencode }}" class="net-unit-row">
              <div class="net-unit-head">
                <div>
                  <div class="adunit-name">{{ u.name or "(unnamed)" }} <span class="pill">{{ u.ad_format }}</span></div>
                  <div class="mono small muted">{{ u.ad_unit_id }}</div>
                </div>
                {% if mapping.admob_mapping_id %}
                  <span class="status status-pushed">Mapped · {{ mapping.admob_mapping_id }}</span>
                {% endif %}
              </div>
              <div class="grid grid-2">
                {% for f in net.ad_unit_fields %}
                  <label><span class="lbl">{{ f.label }}</span>
                    <input name="{{ f.key }}" type="{{ f.type }}" value="{{ mapping.fields.get(f.key, '') if mapping else '' }}" placeholder="{{ f.help }}" />
                  </label>
                {% endfor %}
              </div>
              <button class="btn-secondary btn-sm" type="submit">Save</button>
            </form>
          {% endfor %}
        {% else %}
          <p class="muted small">No ad units cached for this app.</p>
        {% endif %}
      </div>
      {% endfor %}
    </section>
    {% endfor %}
  </div>
</div>

<script>
document.querySelectorAll(".net-tab").forEach(t => t.addEventListener("click", () => {
  const target = t.dataset.tab;
  const sec = t.closest(".net-app-section");
  sec.querySelectorAll(".net-tab").forEach(x => x.classList.toggle("is-active", x === t));
  sec.querySelectorAll(".net-tab-content").forEach(x => x.classList.toggle("is-active", x.id === target));
}));
</script>
{% endif %}
{% endblock %}"""

TEMPLATE_FILES["bidding.html"] = r"""{% extends "base.html" %}
{% block title %}Bidding · Flow{% endblock %}
{% block content %}
<section class="page-head">
  <p class="eyebrow">Bidding setup</p>
  <h1 class="display">3rd-party bidding networks</h1>
  <p class="lede">Set up each bidding network once per app and ad format. The Builder then adds them to your mediation groups automatically.</p>
</section>

{% if not apps %}
<div class="empty">
  <p>No apps cached yet. <form method="post" action="/apps/sync" style="display:inline"><button class="btn-primary" type="submit">↻ Sync from AdMob</button></form></p>
</div>
{% else %}

<div class="bid-wizard">
  <!-- App selector -->
  <div class="bid-app-pick">
    <label class="bid-app-label">
      <span class="lbl">Select App</span>
      <select id="bid-app-select">
        {% for a in apps %}<option value="{{ a.id }}">{{ a.name or a.app_id }} — {{ a.platform }} — {{ a.app_id }}</option>{% endfor %}
      </select>
    </label>
  </div>

  {% for a in apps %}
  {% set summary = saved_summary.get(a.id, {"count":0, "enabled":0, "updated":""}) %}
  <div class="bid-app-block" data-app="{{ a.id }}">

    <!-- Saved-data status banner — auto-loaded from your local database -->
    <div class="bid-loaded-banner {% if summary.count > 0 %}has-saved{% endif %}">
      {% if summary.count > 0 %}
        <span class="bid-loaded-pill">📦 {{ summary.count }} saved configuration{{ '' if summary.count==1 else 's' }} loaded</span>
        <span class="muted small">{{ summary.enabled }} enabled · last updated {{ summary.updated }}</span>
        <span class="bid-db-info muted small">Database: <code>{{ db_url.split('///')[-1] if '///' in db_url else db_url }}</code> · encrypted (AES-256-GCM)</span>
      {% else %}
        <span class="bid-loaded-pill bid-loaded-empty">No saved configurations yet — starting fresh</span>
        <span class="bid-db-info muted small">Will save to <code>{{ db_url.split('///')[-1] if '///' in db_url else db_url }}</code></span>
      {% endif %}
    </div>

    <!-- AUTO-CHECK: existing mediation groups for this app, per format -->
    <section class="bid-existing-card">
      <header class="bid-existing-head">
        <h3>Existing mediation groups</h3>
        <p class="muted small" style="margin:4px 0 0">What's already set up in AdMob for this app. "Not found" just means Flow will create a new one when you push.</p>
      </header>
      <div class="bid-existing-grid" data-app="{{ a.id }}">
        <div class="bid-existing-loading muted small">Loading from AdMob…</div>
      </div>
    </section>

    <!-- STEP 1: Format Support Summary -->
    <section class="bid-step-card">
      <header class="bid-step-head">
        <h3>Step 1 · Choose networks</h3>
        <p class="muted small">Tap a network to turn it on for that ad format.</p>
      </header>

      {% for fmt in formats %}
        {% set supporting = [] %}
        {% for net in networks %}{% if fmt in (net.supports_formats or []) %}{% set _ = supporting.append(net) %}{% endif %}{% endfor %}
        {% set selected = namespace(c=0) %}
        {% for net in supporting %}
          {% set m = mappings.get((a.id, net.code, fmt)) %}
          {% if m and m.enabled %}{% set selected.c = selected.c + 1 %}{% endif %}
        {% endfor %}
        <div class="bid-fmt-summary">
          <header>
            <span class="bid-fmt-label">{{ fmt }}</span>
            <span class="bid-count {% if selected.c > 0 %}is-on{% endif %}">{{ selected.c }} selected</span>
          </header>
          <div class="bid-chips">
            {% if supporting %}
              {% for net in supporting %}
                {% set m = mappings.get((a.id, net.code, fmt), {"enabled": false}) %}
                <a class="bid-chip {% if m.enabled %}is-on{% endif %}" data-target="bid-form-{{ a.id }}-{{ net.code }}-{{ fmt }}" href="#bid-form-{{ a.id }}-{{ net.code }}-{{ fmt }}">{{ net.name }}</a>
              {% endfor %}
            {% else %}
              <span class="muted small">No ad networks available for this format</span>
            {% endif %}
          </div>
        </div>
      {% endfor %}
    </section>

    <!-- STEP 2: Configure Ad Units -->
    <section class="bid-step-card">
      <header class="bid-step-head">
        <h3>Step 2 · Enter each network's details</h3>
        <p class="muted small">Fill in the keys and IDs for the networks you turned on, and pick the ad unit each one applies to.</p>
      </header>

      {% for fmt in formats %}
        {% set supporting = [] %}
        {% for net in networks %}{% if fmt in (net.supports_formats or []) %}{% set _ = supporting.append(net) %}{% endif %}{% endfor %}
        {% if supporting %}
          {% set fmt_units = units_by_app_format.get((a.id, fmt), []) %}
          {% set has_enabled = namespace(b=false) %}
          {% for net in supporting %}
            {% set m = mappings.get((a.id, net.code, fmt)) %}
            {% if m and m.enabled %}{% set has_enabled.b = true %}{% endif %}
          {% endfor %}
          <details class="bid-fmt-section" {% if has_enabled.b %}open{% endif %}>
            <summary>
              <span class="bid-fmt-label">{{ fmt }}</span>
              <span class="bid-section-badge">{{ supporting|length }} networks</span>
            </summary>
            <div class="bid-fmt-section-body">
              {% if not fmt_units %}
                <p class="muted small" style="padding:6px 0">No <b>{{ fmt }}</b> ad units in this app. Sync /apps or create some in AdMob first.</p>
              {% endif %}
              {% for net in supporting %}
                {% set m = mappings.get((a.id, net.code, fmt), {"enabled": false, "ad_unit_id": "", "fields": {}}) %}
                <div id="bid-form-{{ a.id }}-{{ net.code }}-{{ fmt }}" class="bid-net-form {% if m.enabled %}is-on{% endif %}" data-network="{{ net.code }}" data-format="{{ fmt }}">
                  <header class="bid-net-form-head">
                    <label class="bid-net-toggle-wrap">
                      <span class="bidding-toggle">
                        <input type="checkbox" name="enabled" {% if m.enabled %}checked{% endif %} />
                        <span class="bidding-slider"></span>
                      </span>
                      <span class="bid-net-name-big">{{ net.name }}</span>
                    </label>
                    <span class="muted small">Configuration</span>
                  </header>
                  <div class="bid-net-grid">
                    {# Auto-pick the first ad unit of this format when no saved selection #}
                    {% set default_au = fmt_units[0].ad_unit_id if fmt_units else '' %}
                    {% set picked_au = m.ad_unit_id or default_au %}
                    <label>
                      <span class="lbl">Ad Unit ID <span class="muted small" style="font-weight:400">(auto-picked)</span></span>
                      <select name="ad_unit_id">
                        <option value="" {% if not picked_au %}selected{% endif %}>— None —</option>
                        {% for u in fmt_units %}
                          <option value="{{ u.ad_unit_id }}" {% if picked_au == u.ad_unit_id %}selected{% endif %}>{{ u.name }} ({{ u.ad_unit_id.split('/')[-1] }})</option>
                        {% endfor %}
                      </select>
                    </label>
                    {% set total_fields = (net.app_fields or []) + (net.ad_unit_fields or []) %}
                    {% for f in total_fields %}
                      <label>
                        <span class="lbl">{{ f.label }}</span>
                        <input name="{{ f.key }}" type="{{ f.type }}" value="{{ m.fields.get(f.key, '') }}" placeholder="{{ f.help }}" />
                      </label>
                    {% endfor %}
                  </div>
                  {% if not total_fields %}
                    <p class="muted small" style="margin:8px 0 0">{{ net.name }} needs no extra fields — AdMob handles its config internally.</p>
                  {% endif %}
                </div>
              {% endfor %}
            </div>
          </details>
        {% endif %}
      {% endfor %}
    </section>

    <!-- JSON Preview -->
    <section class="bid-step-card bid-preview-card">
      <header class="bid-preview-head">
        <div>
          <h3>Preview</h3>
          <p class="muted small" style="margin:4px 0 0">See exactly what will be saved.</p>
        </div>
        <button type="button" class="btn-secondary btn-sm bid-preview-toggle">Show preview</button>
      </header>
      <pre class="bid-preview-json" style="display:none"></pre>
    </section>

    <!-- Confirm + Save All -->
    <section class="bid-confirm-card">
      <label class="bid-confirm">
        <input type="checkbox" class="bid-confirm-cb" />
        <span>I've reviewed the details above and I'm ready to save.</span>
      </label>
      <button type="button" class="btn-primary btn-lg bid-save-all" disabled>
        💾  Save
      </button>
      <div class="bid-save-result muted small"></div>
    </section>

  </div>
  {% endfor %}
</div>

<script>
const appSel = document.getElementById('bid-app-select');
const FORMATS = {{ formats|tojson }};
const _checkedApps = new Set();

function showApp() {
  const id = appSel.value;
  document.querySelectorAll('.bid-app-block').forEach(b => {
    b.style.display = (b.dataset.app === id) ? '' : 'none';
  });
  // Lazy-fetch existing mediation groups for the newly visible app
  if (id && !_checkedApps.has(id)) {
    _checkedApps.add(id);
    fetchExistingGroups(id);
  }
}
appSel.addEventListener('change', showApp);
showApp();

async function fetchExistingGroups(appId) {
  const grid = document.querySelector(`.bid-existing-grid[data-app="${appId}"]`);
  if (!grid) return;
  grid.innerHTML = '<div class="bid-existing-loading muted small">Loading from AdMob…</div>';
  try {
    const res = await fetch(`/bidding/${appId}/check-groups`);
    if (!res.ok) {
      const txt = await res.text();
      grid.innerHTML = `<div class="muted small" style="color:var(--bad)">Could not fetch: ${txt.slice(0,200)}</div>`;
      return;
    }
    const data = await res.json();
    let html = '';
    FORMATS.forEach(fmt => {
      const groups = (data.by_format || {})[fmt] || [];
      const hasGroups = groups.length > 0;
      html += `
        <div class="bid-existing-row ${hasGroups ? 'has-groups' : 'no-groups'}">
          <div class="bid-existing-fmt">${fmt}</div>
          <div class="bid-existing-status">
            ${hasGroups
              ? groups.map(g => `<span class="bid-existing-pill ${g.state === 'ENABLED' ? 'on' : 'off'}">${escapeHtml(g.name)} <span class="muted">· ${g.line_count} lines · ${g.state || '—'}</span></span>`).join('')
              : `<span class="bid-not-found">Mediation group not found</span>`}
          </div>
        </div>`;
    });
    grid.innerHTML = html;
  } catch (err) {
    grid.innerHTML = `<div class="muted small" style="color:var(--bad)">Error: ${err.message}</div>`;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

// Step 1 chip → toggles the corresponding Step 2 form's enable checkbox + scrolls
document.querySelectorAll('.bid-chip').forEach(chip => {
  chip.addEventListener('click', (e) => {
    e.preventDefault();
    const target = document.getElementById(chip.dataset.target);
    if (!target) return;
    const cb = target.querySelector('input[name=enabled]');
    if (cb) {
      cb.checked = !cb.checked;
      target.classList.toggle('is-on', cb.checked);
      chip.classList.toggle('is-on', cb.checked);
      // Update the format's "X selected" count
      updateFormatCount(chip.closest('.bid-fmt-summary'));
    }
    const det = target.closest('details'); if (det) det.open = true;
    target.scrollIntoView({behavior: 'smooth', block: 'center'});
  });
});

function updateFormatCount(summary) {
  if (!summary) return;
  const chips = summary.querySelectorAll('.bid-chip');
  const onCount = [...chips].filter(c => c.classList.contains('is-on')).length;
  const badge = summary.querySelector('.bid-count');
  if (badge) {
    badge.textContent = `${onCount} selected`;
    badge.classList.toggle('is-on', onCount > 0);
  }
}

// Form toggle ↔ chip visual sync
document.querySelectorAll('.bid-net-form input[name=enabled]').forEach(cb => {
  cb.addEventListener('change', e => {
    const form = e.target.closest('.bid-net-form');
    form.classList.toggle('is-on', e.target.checked);
    const chip = document.querySelector('.bid-chip[data-target="' + form.id + '"]');
    if (chip) {
      chip.classList.toggle('is-on', e.target.checked);
      updateFormatCount(chip.closest('.bid-fmt-summary'));
    }
  });
});

// === Bulk collect → JSON Preview + Save All ===
function currentAppId() { return appSel.value; }

function collectMappings() {
  const block = document.querySelector(`.bid-app-block[data-app="${currentAppId()}"]`);
  if (!block) return [];
  return [...block.querySelectorAll('.bid-net-form')].map(form => {
    const fields = {};
    form.querySelectorAll('.bid-net-grid input').forEach(inp => {
      if (inp.name && inp.name !== 'enabled' && inp.name !== 'ad_unit_id') {
        fields[inp.name] = inp.value || '';
      }
    });
    return {
      network: form.dataset.network,
      format: form.dataset.format,
      enabled: form.querySelector('input[name=enabled]')?.checked || false,
      ad_unit_id: form.querySelector('select[name=ad_unit_id]')?.value || '',
      fields,
    };
  });
}

// JSON Preview toggle (per app block — there are many, the visible one wins)
document.querySelectorAll('.bid-preview-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const pre = btn.closest('.bid-preview-card').querySelector('.bid-preview-json');
    const open = pre.style.display !== 'none';
    if (open) { pre.style.display = 'none'; btn.textContent = 'Show Preview'; }
    else {
      pre.style.display = '';
      pre.textContent = JSON.stringify(collectMappings(), null, 2);
      btn.textContent = 'Hide Preview';
    }
  });
});

// Confirm checkbox gates Save All
document.querySelectorAll('.bid-confirm-cb').forEach(cb => {
  cb.addEventListener('change', e => {
    const card = e.target.closest('.bid-confirm-card');
    card.querySelector('.bid-save-all').disabled = !e.target.checked;
  });
});

// Save All — POST mappings to /bidding/{app}/save-all
document.querySelectorAll('.bid-save-all').forEach(btn => {
  btn.addEventListener('click', async () => {
    const out = btn.closest('.bid-confirm-card').querySelector('.bid-save-result');
    const items = collectMappings();
    if (!items.length) { out.textContent = 'No items to save.'; return; }
    btn.disabled = true;
    const orig = btn.textContent;
    btn.textContent = 'Saving...';
    try {
      const res = await fetch(`/bidding/${currentAppId()}/save-all`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mappings: items}),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Save failed');
      out.innerHTML = `<span style="color:var(--good)">✓ Saved ${data.saved} mapping(s) (${data.enabled} enabled) to database. They will auto-load next time.</span>`;
    } catch (err) {
      out.innerHTML = `<span style="color:var(--bad)">✗ ${err.message}</span>`;
    } finally {
      btn.textContent = orig;
      btn.disabled = !btn.closest('.bid-confirm-card').querySelector('.bid-confirm-cb').checked;
    }
  });
});
</script>
{% endif %}
{% endblock %}"""

CSS_CONTENT = r""":root, :root[data-theme="light"] {
  /* ---- Material 3 color roles — Professional Blue seed (LIGHT) ---- */
  --primary: #0b57d0; --on-primary: #ffffff;
  --primary-container: #d8e2ff; --on-primary-container: #001b3f;
  --secondary: #565f71; --secondary-container: #dae2f9; --on-secondary-container: #131c2b;
  --surface: #eceef7; --surface-container-lowest: #ffffff;
  --surface-container-low: #ffffff; --surface-container: #f3f4fb;
  --surface-container-high: #ebedf6; --surface-container-highest: #e4e6f1;
  --on-surface: #1a1b20; --on-surface-variant: #45464f;
  --outline: #757680; --outline-variant: #d3d5e0;
  --inverse-surface: #2f3036; --inverse-on-surface: #f1f0f7; --inverse-primary: #aac7ff;
  --error: #ba1a1a; --on-error: #ffffff; --error-container: #ffdad6; --on-error-container: #410002;
  --success: #146c2e; --scrim: rgba(0,0,0,0.32);
  --shadow-1: 0 1px 3px rgba(28,40,80,0.10), 0 1px 2px rgba(28,40,80,0.06);
  --shadow-2: 0 4px 10px rgba(28,40,80,0.12), 0 2px 4px rgba(28,40,80,0.07);
  --shadow-3: 0 14px 34px rgba(28,40,80,0.20);
  --accent-rgb: 11,87,208; --good-rgb: 20,108,46; --bad-rgb: 186,26,26;
  --fill-subtle: #eceef3; --fill-hover: rgba(0,0,0,0.045);
  /* ---- back-compat aliases (all existing var(--…) usages adopt M3) ---- */
  --bg: var(--surface); --bg-2: var(--surface-container-low); --bg-3: var(--surface-container-high);
  --line: var(--outline-variant); --line-2: #b7b9c2;
  --ink: var(--on-surface); --ink-dim: var(--on-surface-variant); --ink-mute: #6d7079;
  --accent: var(--primary); --accent-2: #0842a0;
  --good: var(--success); --bad: var(--error);
  --font-display: "Google Sans", "Product Sans", Roboto, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-body: Roboto, "Google Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  --font-mono: "Roboto Mono", ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
  --radius: 8px; --radius-lg: 16px; --radius-pill: 100px;
}
:root[data-theme="dark"] {
  /* ---- Material 3 color roles — Professional Blue seed (DARK) ---- */
  --primary: #aac7ff; --on-primary: #0a305f;
  --primary-container: #274777; --on-primary-container: #d8e2ff;
  --secondary: #bec6dc; --secondary-container: #3e4759; --on-secondary-container: #dae2f9;
  --surface: #121316; --surface-container-lowest: #0d0e11;
  --surface-container-low: #1a1b1f; --surface-container: #1e1f23;
  --surface-container-high: #282a2e; --surface-container-highest: #333438;
  --on-surface: #e3e2e6; --on-surface-variant: #c4c6cf;
  --outline: #8e9099; --outline-variant: #44474e;
  --inverse-surface: #e3e2e6; --inverse-on-surface: #2f3033; --inverse-primary: #0b57d0;
  --error: #ffb4ab; --on-error: #690005; --error-container: #93000a; --on-error-container: #ffdad6;
  --success: #6fd98a; --scrim: rgba(0,0,0,0.55);
  --shadow-1: 0 1px 2px rgba(0,0,0,0.35), 0 1px 3px rgba(0,0,0,0.30);
  --shadow-2: 0 2px 6px rgba(0,0,0,0.45), 0 1px 2px rgba(0,0,0,0.35);
  --shadow-3: 0 10px 30px rgba(0,0,0,0.55);
  --accent-rgb: 170,199,255; --good-rgb: 111,217,138; --bad-rgb: 255,180,171;
  --fill-subtle: #24262b; --fill-hover: rgba(255,255,255,0.06);
  --bg: var(--surface); --bg-2: var(--surface-container-low); --bg-3: var(--surface-container-high);
  --line: var(--outline-variant); --line-2: #5b5e66;
  --ink: var(--on-surface); --ink-dim: var(--on-surface-variant); --ink-mute: #93949c;
  --accent: var(--primary); --accent-2: #c5d9ff;
  --good: var(--success); --bad: var(--error);
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--ink); font-family: var(--font-body); font-size: 15px; line-height: 1.55; -webkit-font-smoothing: antialiased; }
body { background: var(--bg); min-height: 100vh; }
a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-2); }
code, .mono { font-family: var(--font-mono); }
.small { font-size: 12.5px; }
.muted { color: var(--ink-mute); }
.good { color: var(--good); }
.topbar { display: flex; align-items: center; justify-content: space-between; padding: 16px 36px; border-bottom: 1px solid var(--line); background: linear-gradient(180deg, rgba(255,255,255,0.02), transparent); position: sticky; top: 0; z-index: 10; backdrop-filter: blur(8px); }
.brand-link { display: inline-flex; align-items: center; gap: 10px; color: var(--ink); }
.brand-mark { font-size: 22px; color: var(--accent); }
.brand-name { font-family: var(--font-display); font-weight: 600; font-size: 19px; letter-spacing: -0.01em; }
.brand-dot { color: var(--accent-2); }
.topnav { display: flex; align-items: center; gap: 18px; }
.topnav a { color: var(--ink-dim); font-size: 14px; }
.topnav a:hover { color: var(--ink); }
.topnav a.cta { color: var(--accent); }
.topnav .sep { width: 1px; height: 18px; background: var(--line); }
.user-chip { display: inline-flex; align-items: center; gap: 8px; color: var(--ink-mute); font-size: 13px; }
.user-chip img { width: 22px; height: 22px; border-radius: 50%; border: 1px solid var(--line-2); }
.topnav .logout { color: var(--ink-mute); font-size: 13px; }
.content { max-width: 1240px; margin: 0 auto; padding: 36px 36px 80px; }
.footer { max-width: 1240px; margin: 0 auto; padding: 24px 36px 40px; color: var(--ink-mute); font-size: 12.5px; }
.footer-version { color: var(--accent); text-decoration: none; font-family: var(--font-mono); font-weight: 500; }
.footer-version:hover { text-decoration: underline; }
.changelog { max-width: 780px; }
.changelog-entry { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius-lg); padding: 20px 24px; margin-bottom: 16px; }
.changelog-entry.is-current { border-color: var(--accent); box-shadow: 0 0 0 1px rgba(var(--accent-rgb),0.25); }
.changelog-head { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
.changelog-ver { font-family: var(--font-mono); font-size: 20px; font-weight: 600; color: var(--accent); }
.changelog-title { font-family: var(--font-display); font-size: 16px; color: var(--ink); }
.changelog-date { color: var(--ink-mute); margin-left: auto; }
.changelog-list { margin: 0; padding-left: 20px; }
.changelog-list li { margin: 7px 0; color: var(--ink-dim); font-size: 13.5px; line-height: 1.5; }
.footer-sep { margin: 0 10px; opacity: 0.5; }
.page-head { margin-bottom: 28px; }
.row-between { display: flex; align-items: center; justify-content: space-between; gap: 18px; flex-wrap: wrap; }
.eyebrow { font-family: var(--font-mono); font-size: 11.5px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); margin: 0 0 8px; }
.display { font-family: var(--font-display); font-weight: 400; font-size: clamp(28px, 4.2vw, 44px); line-height: 1.08; letter-spacing: -0.02em; margin: 0; }
.display em { font-style: italic; color: var(--accent); }
.lede { color: var(--ink-dim); max-width: 70ch; }
.section-title { font-family: var(--font-display); font-weight: 500; font-size: 22px; margin: 36px 0 14px; letter-spacing: -0.01em; }
.grid { display: grid; gap: 18px; }
.grid-2 { grid-template-columns: repeat(2, 1fr); }
.grid-3 { grid-template-columns: repeat(3, 1fr); }
@media (max-width: 800px) { .grid-2, .grid-3 { grid-template-columns: 1fr; } }
.cta-row { display: flex; gap: 12px; margin: 18px 0 6px; flex-wrap: wrap; }
.card { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius-lg); padding: 22px 22px 18px; position: relative; }
.card-label { font-family: var(--font-mono); font-size: 11.5px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-mute); margin: 0 0 8px; }
.card-value { font-family: var(--font-display); font-size: 30px; margin: 0; letter-spacing: -0.01em; }
.card-value.mono { font-family: var(--font-mono); font-size: 16px; word-break: break-all; }
.card-link { display: inline-block; margin-top: 14px; font-size: 13px; }
.workflow-steps { list-style: none; padding: 0; margin: 12px 0 0; }
.workflow-steps li { display: flex; align-items: baseline; gap: 16px; padding: 10px 0; border-bottom: 1px dashed var(--line); }
.workflow-steps li:last-child { border-bottom: 0; }
.step-no { font-family: var(--font-mono); font-size: 12px; color: var(--accent); width: 36px; flex-shrink: 0; letter-spacing: 0.04em; }
.step-text { color: var(--ink-dim); }
.done { color: var(--good); margin-left: 8px; font-family: var(--font-mono); }
.btn-primary, .btn-secondary, .btn-ghost, .btn-danger { display: inline-flex; align-items: center; gap: 8px; font: 500 14px/1 var(--font-body); padding: 11px 18px; border-radius: var(--radius); border: 1px solid transparent; cursor: pointer; transition: all .15s ease; text-decoration: none; }
.btn-primary { background: var(--accent); color: #1a1407; border-color: var(--accent); }
.btn-primary:hover { background: var(--accent-2); border-color: var(--accent-2); color: #1a1407; }
.btn-primary.btn-lg { padding: 14px 22px; font-size: 15px; }
.btn-secondary { background: transparent; color: var(--ink); border-color: var(--line-2); }
.btn-secondary:hover { border-color: var(--ink-dim); }
.btn-ghost { background: transparent; color: var(--ink-dim); border-color: transparent; }
.btn-ghost:hover { color: var(--ink); border-color: var(--line); }
.btn-danger { background: transparent; color: var(--bad); border-color: var(--line); }
.btn-danger:hover { border-color: var(--bad); }
.btn-sm { padding: 6px 10px; font-size: 12.5px; }
button:disabled { opacity: .5; cursor: not-allowed; }
.g-mark { display: inline-grid; place-items: center; width: 28px; height: 28px; border-radius: 50%; background: #ffffff; box-shadow: 0 1px 2px rgba(0,0,0,0.18); margin-right: 2px; }
.g-mark svg { display: block; }
.login-wrap { display: grid; grid-template-columns: 1.4fr 0.8fr; gap: 60px; align-items: start; padding-top: 30px; }
@media (max-width: 900px) { .login-wrap { grid-template-columns: 1fr; gap: 30px; } }
.login-card .fineprint { color: var(--ink-mute); font-size: 12.5px; margin-top: 16px; }
.login-card .fineprint code { background: var(--bg-3); padding: 2px 6px; border-radius: 4px; color: var(--accent); }
.login-card .btn-primary { margin-top: 24px; padding: 14px 22px; font-size: 15px; }
.login-side { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius-lg); padding: 24px; }
.login-side h3 { font-family: var(--font-display); font-weight: 500; margin: 0 0 14px; font-size: 18px; }
.login-side ol { padding-left: 22px; color: var(--ink-dim); margin: 0; }
.login-side li { padding: 4px 0; }
.table { width: 100%; border-collapse: collapse; background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius-lg); overflow: hidden; }
.table th, .table td { padding: 11px 14px; text-align: left; border-bottom: 1px solid var(--line); }
.table th { font-size: 11.5px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--ink-mute); background: rgba(0,0,0,0.15); font-weight: 500; font-family: var(--font-mono); }
.table tr:last-child td { border-bottom: 0; }
.table tr:hover td { background: rgba(255,255,255,0.015); }
.pill { display: inline-block; padding: 2px 8px; border-radius: 999px; background: var(--bg-3); border: 1px solid var(--line-2); font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.04em; color: var(--ink-dim); }
.pill-android { color: var(--good); border-color: rgba(var(--good-rgb),0.3); }
.pill-ios { color: #9bb7e2; border-color: rgba(155,183,226,0.3); }
.pill-good { background: rgba(var(--good-rgb),0.18); color: var(--good); }
.status { display: inline-block; padding: 3px 9px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.05em; }
.status-draft { color: var(--ink-mute); background: rgba(132,124,105,0.12); }
.status-generated { color: var(--accent); background: rgba(var(--accent-rgb),0.12); }
.status-pushed { color: var(--good); background: rgba(var(--good-rgb),0.16); }
.status-pushed_partial { color: var(--accent); background: rgba(var(--accent-rgb),0.16); }
.status-push_failed { color: var(--bad); background: rgba(226,112,91,0.14); }
label { display: flex; flex-direction: column; gap: 6px; }
.lbl { color: var(--ink-dim); font-size: 12.5px; }
input[type="text"], input[type="number"], input[type="password"], input:not([type]), select, textarea { background: var(--bg-3); color: var(--ink); border: 1px solid var(--line-2); border-radius: var(--radius); padding: 9px 12px; font: 400 14px/1.3 var(--font-body); color-scheme: dark; }
select option { background: var(--bg-2); color: var(--ink); }
input:focus, select:focus, textarea:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(var(--accent-rgb),0.12); }
.builder-grid { display: grid; grid-template-columns: 1.4fr 0.8fr; gap: 28px; align-items: start; }
@media (max-width: 1000px) { .builder-grid { grid-template-columns: 1fr; } }
.builder-step { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius-lg); padding: 18px 20px; margin-bottom: 18px; }
.builder-step legend { padding: 0 6px; color: var(--ink-dim); font-family: var(--font-mono); font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; }
.builder-step legend .num { color: var(--accent); margin-right: 8px; }
.check-row { flex-direction: row; align-items: center; gap: 8px; margin-top: 12px; color: var(--ink-dim); font-size: 13px; }
.radio-row { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
.radio-row label { flex-direction: row; align-items: center; gap: 10px; color: var(--ink-dim); }
.form-actions { display: flex; gap: 12px; align-items: center; padding-top: 4px; flex-wrap: wrap; }
.preview-panel { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius-lg); padding: 20px; position: sticky; top: 84px; }
.kv { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px dashed var(--line); font-size: 13.5px; }
.kv:last-child { border-bottom: 0; }
.kv span { color: var(--ink-mute); }
.kv b { color: var(--ink); font-weight: 500; }
.adunit-cards { display: flex; flex-direction: column; gap: 8px; max-height: 360px; overflow-y: auto; padding-right: 6px; }
.adunit-card { display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--fill-subtle); border: 1px solid var(--line); border-radius: var(--radius); gap: 12px; cursor: pointer; transition: border-color .12s ease, background .12s ease; }
.adunit-card:hover { border-color: var(--ink-mute); background: var(--fill-hover); }
.adunit-card.is-selected { border-color: var(--accent); background: rgba(var(--accent-rgb),0.06); }
.adunit-card.is-selected:hover { background: rgba(var(--accent-rgb),0.10); }
.adunit-card .adunit-name { font-weight: 500; }
.adunit-card .adunit-id { color: var(--ink-mute); }
.sel-unit { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 8px 10px; background: var(--fill-subtle); border: 1px solid var(--line); border-radius: var(--radius); margin-bottom: 8px; }
.sel-unit-info { min-width: 0; }
.sel-unit-name { font-weight: 500; font-size: 13.5px; }
.sel-unit-remove { flex: none; width: 26px; height: 26px; border-radius: 6px; border: 1px solid var(--line-2); background: transparent; color: var(--bad); cursor: pointer; font-size: 14px; line-height: 1; }
.sel-unit-remove:hover { border-color: var(--bad); background: rgba(224,79,79,0.08); }
.country-chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0; max-height: 220px; overflow-y: auto; }
.country-chip { background: var(--bg-3); border: 1px solid var(--line-2); color: var(--ink-dim); padding: 6px 10px; border-radius: 999px; font-family: var(--font-mono); font-size: 12px; cursor: pointer; }
.country-chip:hover { border-color: var(--ink-mute); }
.country-chip.is-selected { background: rgba(var(--accent-rgb),0.16); color: var(--accent); border-color: var(--accent); }
#push-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.74); z-index: 9999; display: flex; align-items: center; justify-content: center; }
.push-modal { background: var(--bg-2); border: 1px solid var(--line-2); border-radius: var(--radius-lg); padding: 28px 32px; width: min(440px, 90vw); text-align: center; box-shadow: 0 20px 60px rgba(0,0,0,0.55); }
.push-title { font-family: var(--font-display); font-size: 18px; font-weight: 500; margin: 0 0 14px; }
.push-count { font-family: var(--font-mono); font-size: 32px; color: var(--accent); margin-bottom: 14px; letter-spacing: 1px; }
.push-bar { height: 12px; background: var(--bg-3); border-radius: 999px; overflow: hidden; border: 1px solid var(--line); }
.push-bar-fill { height: 100%; width: 0%; background: var(--accent); border-radius: 999px; transition: width .35s ease; }
.push-msg { color: var(--ink-dim); font-size: 13px; margin: 14px 0 4px; min-height: 18px; }
.push-note { color: var(--ink-mute); font-size: 11.5px; margin: 0; }
#snackbar { position: fixed; left: 50%; bottom: 28px; transform: translateX(-50%); background: var(--bg-2); border: 1px solid var(--accent); color: var(--ink); padding: 12px 20px; border-radius: 10px; font-size: 13px; z-index: 10000; opacity: 0; pointer-events: none; transition: opacity .25s ease; box-shadow: 0 8px 30px rgba(0,0,0,0.45); max-width: 90vw; }
#snackbar.show { opacity: 1; }
.report-card { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius-lg); padding: 18px 20px; margin-bottom: 16px; }
.report-card-head { display: flex; justify-content: space-between; align-items: baseline; gap: 16px; margin-bottom: 14px; flex-wrap: wrap; }
.report-card-title { font-family: var(--font-display); font-size: 18px; font-weight: 500; }
.report-card-summary { color: var(--ink-dim); font-size: 13px; }
.metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; }
@media (max-width: 700px) { .metric-grid { grid-template-columns: repeat(2, 1fr); } }
.metric { background: var(--bg-3); border: 1px solid var(--line); border-radius: var(--radius); padding: 10px 12px; }
.metric-label { display: block; font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-mute); margin-bottom: 4px; }
.metric-value { font-family: var(--font-display); font-size: 20px; color: var(--accent); }
.metric-value.good { color: var(--good); }
.line-table { margin-top: 12px; border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; }
.line-table-head { display: grid; grid-template-columns: 50px 1fr 1.4fr; gap: 10px; padding: 8px 12px; background: var(--fill-subtle); font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-mute); }
.line-table-row { display: grid; grid-template-columns: 50px 1fr 1.4fr; gap: 10px; padding: 8px 12px; border-top: 1px solid var(--line); align-items: center; }
.default-network-note { margin-top: 12px; padding: 10px 14px; background: rgba(var(--accent-rgb),0.07); border: 1px solid rgba(var(--accent-rgb),0.25); border-radius: var(--radius); color: var(--ink-dim); font-size: 13px; }
.networks-page { display: grid; grid-template-columns: 220px 1fr; gap: 28px; align-items: start; }
@media (max-width: 900px) { .networks-page { grid-template-columns: 1fr; } }
.net-app-list { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius-lg); padding: 16px; position: sticky; top: 84px; }
.net-app-list h3 { margin: 0 0 12px; font-family: var(--font-display); font-size: 16px; font-weight: 500; }
.net-app-link { display: block; padding: 10px 12px; border-radius: var(--radius); color: var(--ink-dim); margin-bottom: 6px; }
.net-app-link:hover { background: var(--fill-hover); color: var(--ink); }
.net-app-section { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius-lg); padding: 22px; margin-bottom: 22px; }
.net-tabs { display: flex; gap: 4px; flex-wrap: wrap; margin: 20px 0 16px; border-bottom: 1px solid var(--line); }
.net-tab { background: transparent; color: var(--ink-mute); border: 0; border-bottom: 2px solid transparent; padding: 10px 14px; cursor: pointer; font: 500 13px/1 var(--font-body); }
.net-tab:hover { color: var(--ink); }
.net-tab.is-active { color: var(--accent); border-bottom-color: var(--accent); }
.net-tab-content { display: none; }
.net-tab-content.is-active { display: block; }
.net-tab-content h4 { font-family: var(--font-display); font-weight: 500; margin: 0 0 12px; font-size: 16px; }
.net-form { padding: 14px; background: var(--fill-subtle); border: 1px solid var(--line); border-radius: var(--radius); margin-bottom: 10px; }
.net-unit-row { padding: 12px 14px; background: var(--fill-subtle); border: 1px solid var(--line); border-radius: var(--radius); margin-bottom: 8px; }
.net-unit-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 10px; flex-wrap: wrap; }
.calc-explainer { background: var(--bg-3); border: 1px solid var(--line); border-radius: var(--radius); padding: 12px 16px; color: var(--ink-dim); font-size: 13px; margin: 18px 0; }
.callout { background: rgba(var(--accent-rgb),0.08); border: 1px solid rgba(var(--accent-rgb),0.25); border-radius: var(--radius); padding: 12px 16px; color: var(--ink-dim); font-size: 13px; margin-top: 24px; }
.empty { background: var(--bg-2); border: 1px dashed var(--line-2); border-radius: var(--radius-lg); padding: 40px; text-align: center; color: var(--ink-dim); }
.empty p { margin-top: 0; }
.alert { border-radius: var(--radius); padding: 12px 16px; margin-bottom: 20px; font-size: 14px; }
.alert-warn { background: rgba(var(--accent-rgb),0.07); border: 1px solid rgba(var(--accent-rgb),0.3); color: var(--accent); }
.actions-col { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.actions-col form { display: inline; }
.forensic-block { background: var(--bg-3); border: 1px solid var(--line); border-radius: var(--radius); padding: 12px; font-family: var(--font-mono); font-size: 11.5px; color: var(--ink-dim); overflow-x: auto; max-height: 240px; }

/* Bidding setup — ADFLUX-style wizard (Step 1 chips + Step 2 forms) */
.bid-wizard { display: flex; flex-direction: column; gap: 18px; }

.bid-app-pick { padding: 18px 20px; background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius); }
.bid-app-label { display: flex; flex-direction: column; gap: 6px; }
.bid-app-label .lbl { font-size: 11px; color: var(--ink-mute); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }
.bid-app-label select { padding: 12px 14px; background: var(--bg-3); border: 1px solid var(--line); border-radius: 8px; color: var(--ink); font-size: 14px; cursor: pointer; width: 100%; }
.bid-app-label select:focus { border-color: var(--accent); outline: none; }

.bid-app-block { display: flex; flex-direction: column; gap: 18px; }

.bid-step-card { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius); padding: 22px 26px; }
.bid-step-head { margin-bottom: 18px; }
.bid-step-head h3 { font-size: 18px; font-weight: 600; color: var(--ink); margin: 0 0 4px; }
.bid-step-head p { margin: 0; }

.bid-fmt-summary { padding: 14px 0; border-bottom: 1px solid var(--line); }
.bid-fmt-summary:last-child { border-bottom: none; }
.bid-fmt-summary > header { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
.bid-fmt-label { font-family: var(--font-mono); font-size: 13px; letter-spacing: 0.06em; color: var(--ink); font-weight: 600; }
.bid-count { font-size: 11px; padding: 4px 10px; border-radius: 999px; background: var(--bg-3); color: var(--ink-mute); border: 1px solid var(--line); white-space: nowrap; }
.bid-count.is-on { background: rgba(var(--accent-rgb),0.12); color: var(--accent); border-color: rgba(var(--accent-rgb),0.4); }
.bid-chips { display: flex; flex-wrap: wrap; gap: 8px; }
.bid-chip { display: inline-flex; padding: 8px 16px; border-radius: 999px; background: var(--bg-3); border: 1px solid var(--line); color: var(--ink-dim); font-size: 13px; cursor: pointer; transition: all 0.15s; user-select: none; font-weight: 500; }
.bid-chip:hover { border-color: rgba(var(--accent-rgb),0.4); color: var(--ink); }
.bid-chip.is-on { background: var(--accent-2); border-color: var(--accent-2); color: white; }
.bid-chip.is-on:hover { background: var(--accent); border-color: var(--accent); color: white; }

.bid-fmt-section { background: var(--bg-3); border: 1px solid var(--line); border-radius: var(--radius); margin-bottom: 12px; overflow: hidden; }
.bid-fmt-section > summary { cursor: pointer; padding: 14px 18px; display: flex; align-items: center; justify-content: space-between; gap: 12px; list-style: none; transition: background 0.15s; }
.bid-fmt-section > summary::-webkit-details-marker { display: none; }
.bid-fmt-section > summary:hover { background: var(--bg-2); }
.bid-fmt-section[open] > summary { border-bottom: 1px solid var(--line); }
.bid-fmt-section-body { padding: 18px; display: flex; flex-direction: column; gap: 14px; }

.bid-net-form { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius); padding: 16px 18px; transition: border-color 0.2s, background 0.2s; display: flex; flex-direction: column; gap: 12px; }
.bid-net-form.is-on { border-color: rgba(var(--accent-rgb),0.45); background: rgba(var(--accent-rgb),0.03); }
.bid-net-form-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.bid-net-toggle-wrap { display: flex; align-items: center; gap: 12px; cursor: pointer; user-select: none; }
.bid-net-name-big { font-weight: 600; color: var(--ink); font-size: 15px; }
.bid-net-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
.bid-net-grid label { display: flex; flex-direction: column; gap: 4px; }
.bid-net-grid .lbl { font-size: 11px; color: var(--ink-mute); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 500; }
.bid-net-grid input, .bid-net-grid select { width: 100%; padding: 10px 12px; background: var(--bg-3); border: 1px solid var(--line); border-radius: 8px; color: var(--ink); font-size: 13px; font-family: var(--font-mono); }
.bid-net-grid input:focus, .bid-net-grid select:focus { border-color: var(--accent); outline: none; }
.bid-net-form-foot { display: flex; justify-content: flex-end; padding-top: 8px; border-top: 1px dashed var(--line); }

.bid-section-badge { font-size: 11px; padding: 4px 10px; border-radius: 999px; background: var(--bg-2); color: var(--ink-mute); border: 1px solid var(--line); white-space: nowrap; }
.bid-preview-card { padding: 18px 22px; }
.bid-preview-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; }
.bid-preview-head h3 { font-size: 16px; font-weight: 600; color: var(--ink); margin: 0; }
.bid-preview-json { background: var(--bg-3); border: 1px solid var(--line); border-radius: 8px; padding: 14px; margin-top: 14px; max-height: 360px; overflow: auto; font-family: var(--font-mono); font-size: 12px; color: var(--ink-dim); }

.bid-confirm-card { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px 22px; display: flex; flex-direction: column; gap: 16px; }
.bid-confirm { display: flex; align-items: flex-start; gap: 12px; padding: 12px 16px; background: rgba(var(--accent-rgb),0.06); border: 1px solid rgba(var(--accent-rgb),0.25); border-radius: 8px; cursor: pointer; user-select: none; }
.bid-confirm input { margin-top: 3px; width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }
.bid-confirm span { font-size: 13px; color: var(--ink); line-height: 1.5; }
.bid-save-all { width: 100%; padding: 14px 20px; font-size: 15px; font-weight: 600; background: var(--accent-2); border: 1px solid var(--accent-2); color: white; border-radius: var(--radius); cursor: pointer; transition: all 0.15s; display: flex; align-items: center; justify-content: center; gap: 10px; }
.bid-save-all:hover:not(:disabled) { background: var(--accent); border-color: var(--accent); }
.bid-save-all:disabled { opacity: 0.4; cursor: not-allowed; }
.bid-save-result { text-align: center; }

/* Existing mediation groups auto-check panel */
.bid-existing-card { background: var(--bg-2); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px 22px; }
.bid-existing-head { margin-bottom: 14px; }
.bid-existing-head h3 { font-size: 16px; font-weight: 600; color: var(--ink); margin: 0; display: flex; align-items: center; gap: 8px; }
.bid-existing-head h3::before { content: "🔍"; font-size: 14px; }
.bid-existing-grid { display: flex; flex-direction: column; gap: 8px; }
.bid-existing-loading { padding: 12px 0; }
.bid-existing-row { display: grid; grid-template-columns: 140px 1fr; align-items: center; gap: 16px; padding: 10px 14px; background: var(--bg-3); border: 1px solid var(--line); border-radius: 6px; }
.bid-existing-row.has-groups { border-color: rgba(var(--good-rgb),0.3); background: rgba(var(--good-rgb),0.04); }
.bid-existing-fmt { font-family: var(--font-mono); font-size: 13px; letter-spacing: 0.04em; color: var(--ink); font-weight: 600; }
.bid-existing-status { display: flex; flex-wrap: wrap; gap: 6px; }
.bid-existing-pill { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; padding: 4px 10px; border-radius: 999px; background: var(--bg-2); border: 1px solid var(--line); color: var(--ink); }
.bid-existing-pill.on { border-color: rgba(var(--good-rgb),0.4); color: var(--good); }
.bid-existing-pill.off { color: var(--ink-mute); }
.bid-not-found { font-size: 12px; color: var(--ink-mute); font-style: italic; }

/* "Saved configurations loaded" status banner */
.bid-loaded-banner { background: var(--bg-3); border: 1px solid var(--line); border-radius: var(--radius); padding: 10px 16px; display: flex; flex-wrap: wrap; align-items: center; gap: 14px; font-size: 13px; }
.bid-loaded-banner.has-saved { border-color: rgba(var(--good-rgb),0.35); background: rgba(var(--good-rgb),0.05); }
.bid-loaded-pill { padding: 4px 12px; border-radius: 999px; background: rgba(var(--good-rgb),0.15); border: 1px solid rgba(var(--good-rgb),0.4); color: var(--good); font-weight: 600; font-size: 12px; }
.bid-loaded-pill.bid-loaded-empty { background: var(--bg-2); border-color: var(--line); color: var(--ink-mute); font-weight: 500; }
.bid-db-info { margin-left: auto; }
.bid-db-info code { font-family: var(--font-mono); background: var(--bg-2); padding: 2px 6px; border-radius: 4px; border: 1px solid var(--line); }

/* Builder: "Include All Bidding Networks" callout + iOS-style toggle */
.bidding-callout { background: var(--bg-3); border: 1px solid var(--line); border-radius: var(--radius); padding: 14px 18px; margin: 14px 0; transition: border-color 0.2s, background 0.2s; }
.bidding-callout.is-on { border-color: rgba(var(--accent-rgb),0.5); background: rgba(var(--accent-rgb),0.06); }
.bidding-callout-head { display: flex; align-items: center; justify-content: space-between; gap: 18px; }
.bidding-callout-head > div { flex: 1; }
.bidding-callout-head strong { font-size: 14px; color: var(--ink); }
.bidding-toggle { position: relative; display: inline-block; width: 48px; height: 26px; flex-shrink: 0; cursor: pointer; }
.bidding-toggle input { opacity: 0; width: 0; height: 0; }
.bidding-slider { position: absolute; inset: 0; background: var(--bg-2); border: 1px solid var(--line); border-radius: 999px; transition: background 0.2s, border-color 0.2s; }
.bidding-slider::before { content: ""; position: absolute; left: 3px; top: 3px; width: 18px; height: 18px; background: var(--ink-mute); border-radius: 50%; transition: transform 0.2s, background 0.2s; }
.bidding-toggle input:checked + .bidding-slider { background: var(--accent); border-color: var(--accent); }
.bidding-toggle input:checked + .bidding-slider::before { transform: translateX(22px); background: var(--on-primary); }

/* ======================================================================
   MATERIAL 3 REFINEMENTS  (appended — override earlier component styles)
   Full sans typography, tonal surfaces, pill buttons with state layers,
   clean cards, M3 text fields, top app bar, theme toggle, dialog, snackbar.
   ====================================================================== */
html, body { font-size: 14.5px; line-height: 1.5; }
::selection { background: rgba(var(--accent-rgb),0.24); }
* { scrollbar-color: var(--outline) transparent; }

/* ---- Top app bar ---- */
.topbar { padding: 12px 24px; background: var(--surface-container-low); border-bottom: 1px solid var(--outline-variant); backdrop-filter: none; }
.brand-mark { color: var(--primary); font-size: 22px; }
.brand-name { font-family: var(--font-display); font-weight: 600; font-size: 20px; letter-spacing: -0.01em; color: var(--on-surface); }
.brand-dot { color: var(--primary); }
.topnav { gap: 4px; }
.topnav a { color: var(--on-surface-variant); font-size: 13.5px; font-weight: 500; padding: 8px 12px; border-radius: var(--radius-pill); transition: background .15s ease, color .15s ease; }
.topnav a:hover { color: var(--on-surface); background: var(--fill-hover); }
.topnav a.cta { color: var(--primary); }
.topnav a.cta:hover { background: rgba(var(--accent-rgb),0.10); }
.topnav .sep { background: var(--outline-variant); margin: 0 4px; }
.user-chip { color: var(--on-surface-variant); font-size: 12.5px; padding-left: 6px; }
.user-chip img { border: 1px solid var(--outline-variant); }
.topnav .logout { color: var(--on-surface-variant); padding: 8px 12px; border-radius: var(--radius-pill); }
.topnav .logout:hover { background: var(--fill-hover); color: var(--on-surface); }

/* ---- Theme toggle (added in base.html) ---- */
.theme-toggle { display: inline-flex; align-items: center; justify-content: center; width: 40px; height: 40px; border-radius: var(--radius-pill); border: none; background: transparent; color: var(--on-surface-variant); cursor: pointer; font-size: 18px; line-height: 1; transition: background .15s ease, color .15s ease; }
.theme-toggle:hover { background: var(--fill-hover); color: var(--on-surface); }
.theme-toggle .icon-dark { display: none; }
:root[data-theme="dark"] .theme-toggle .icon-dark { display: inline; }
:root[data-theme="dark"] .theme-toggle .icon-light { display: none; }

/* ---- Typography ---- */
.display { font-family: var(--font-display); font-weight: 600; letter-spacing: -0.02em; color: var(--on-surface); }
.display em { font-style: normal; color: var(--primary); }
.section-title { font-family: var(--font-display); font-weight: 600; color: var(--on-surface); }
.eyebrow { font-family: var(--font-body); color: var(--primary); font-weight: 600; letter-spacing: 0.08em; }
.card-label, .metric-label, .line-table-head, .step-no { font-family: var(--font-body); }
.card-value { font-family: var(--font-display); font-weight: 600; color: var(--on-surface); }
.lede, .step-text { color: var(--on-surface-variant); }

/* ---- Buttons: M3 pill shape + state layers ---- */
.btn-primary, .btn-secondary, .btn-ghost, .btn-danger { font: 500 14px/1 var(--font-body); padding: 0 22px; height: 40px; border-radius: var(--radius-pill); border: 1px solid transparent; letter-spacing: 0.01em; position: relative; overflow: hidden; }
.btn-primary { background: var(--primary); color: var(--on-primary); border-color: var(--primary); box-shadow: var(--shadow-1); }
.btn-primary:hover { background: var(--accent-2); border-color: var(--accent-2); color: var(--on-primary); box-shadow: var(--shadow-2); }
.btn-primary:active { box-shadow: none; }
.btn-primary.btn-lg { height: 48px; padding: 0 28px; font-size: 15px; }
.btn-secondary { background: transparent; color: var(--primary); border-color: var(--outline); }
.btn-secondary:hover { border-color: var(--primary); background: rgba(var(--accent-rgb),0.08); color: var(--primary); }
.btn-ghost { background: transparent; color: var(--primary); border-color: transparent; }
.btn-ghost:hover { background: rgba(var(--accent-rgb),0.10); color: var(--primary); border-color: transparent; }
.btn-danger { background: transparent; color: var(--error); border-color: var(--outline); }
.btn-danger:hover { background: rgba(var(--bad-rgb),0.09); border-color: var(--error); color: var(--error); }
.btn-sm { height: 32px; padding: 0 14px; font-size: 13px; }

/* ---- Cards & surfaces: tonal elevation, softer radius ---- */
.card { background: var(--surface-container-low); border: none; border-radius: var(--radius-lg); box-shadow: var(--shadow-1); }
:root[data-theme="dark"] .card { border: 1px solid var(--outline-variant); }
.card:hover { box-shadow: var(--shadow-2); }
.card-link { color: var(--primary); font-weight: 500; }
.report-card, .net-app-section, .net-app-list, .bid-app-pick, .bid-step-card,
.bid-confirm-card, .bid-existing-card, .empty, .changelog-entry, .login-card, .login-side { border-radius: var(--radius-lg); }
.report-card, .net-app-section, .bid-step-card { box-shadow: var(--shadow-1); }
.changelog-entry.is-current { border-color: var(--primary); box-shadow: 0 0 0 1px rgba(var(--accent-rgb),0.30); }
.changelog-ver, .changelog-title { color: var(--on-surface); }
.changelog-ver { color: var(--primary); }

/* ---- M3 text fields ---- */
input[type="text"], input[type="number"], input[type="password"], input:not([type]), select, textarea {
  background: var(--surface-container-highest); color: var(--on-surface);
  border: 1px solid var(--outline); border-radius: var(--radius);
  padding: 11px 14px; font: 400 14px/1.3 var(--font-body); color-scheme: light dark;
  transition: border-color .15s ease, box-shadow .15s ease; }
input:focus, select:focus, textarea:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 2px rgba(var(--accent-rgb),0.28); }
input::placeholder, textarea::placeholder { color: var(--on-surface-variant); opacity: 0.75; }

/* ---- Chips (country / account / bidding) ---- */
.country-chip, .bid-chip, .bid-count, .bid-section-badge, .pill { border-radius: var(--radius-pill); }
.country-chip { background: transparent; border: 1px solid var(--outline); color: var(--on-surface-variant); }
.country-chip:hover { background: var(--fill-hover); border-color: var(--outline); }
.country-chip.is-selected { background: rgba(var(--accent-rgb),0.14); color: var(--primary); border-color: var(--primary); }
.bid-chip { background: transparent; border: 1px solid var(--outline); color: var(--on-surface-variant); }
.bid-chip:hover { border-color: var(--primary); color: var(--on-surface); background: var(--fill-hover); }
.bid-chip.is-on, .bid-chip.is-on:hover { background: var(--primary); border-color: var(--primary); color: var(--on-primary); }
.pill { background: var(--secondary-container); color: var(--on-secondary-container); border: none; padding: 3px 10px; font-size: 11px; font-weight: 500; }

/* ---- Selected-unit list / adunit cards ---- */
.adunit-card, .sel-unit, .metric, .net-form, .net-unit-row, .calc-explainer,
.forensic-block, .bid-net-form, .bid-fmt-section, .bid-existing-row, .bidding-callout { border-radius: var(--radius); }
.adunit-card:hover { border-color: var(--primary); background: var(--fill-hover); }
.adunit-card.is-selected { border-color: var(--primary); background: rgba(var(--accent-rgb),0.08); }
.metric-value { font-family: var(--font-display); color: var(--primary); font-weight: 600; }
.net-tab.is-active { color: var(--primary); border-bottom-color: var(--primary); }

/* ---- Alerts / callouts ---- */
.alert-warn, .default-network-note, .callout { background: rgba(var(--accent-rgb),0.08); border: 1px solid rgba(var(--accent-rgb),0.28); color: var(--on-surface-variant); border-radius: var(--radius); }
.alert-warn { color: var(--on-surface); }

/* ---- Bidding save-all button → filled M3 ---- */
.bid-save-all { background: var(--primary); border: 1px solid var(--primary); color: var(--on-primary); border-radius: var(--radius-pill); height: 48px; }
.bid-save-all:hover:not(:disabled) { background: var(--accent-2); border-color: var(--accent-2); box-shadow: var(--shadow-2); }

/* ======================================================================
   M3 DIALOG (replaces native confirm/alert) + SCRIM
   ====================================================================== */
.m3-scrim { position: fixed; inset: 0; background: var(--scrim); z-index: 10050; display: flex; align-items: center; justify-content: center; padding: 20px; opacity: 0; pointer-events: none; transition: opacity .18s ease; }
.m3-scrim.show { opacity: 1; pointer-events: auto; }
.m3-dialog { background: var(--surface-container-high); color: var(--on-surface); border-radius: 28px; width: min(420px, 100%); padding: 24px; box-shadow: var(--shadow-3); transform: translateY(8px) scale(0.98); transition: transform .18s ease; }
.m3-scrim.show .m3-dialog { transform: none; }
.m3-dialog h3 { font-family: var(--font-display); font-weight: 600; font-size: 20px; margin: 0 0 12px; color: var(--on-surface); }
.m3-dialog p { margin: 0 0 22px; color: var(--on-surface-variant); font-size: 14px; line-height: 1.5; }
.m3-dialog-actions { display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap; }

/* ---- Push progress dialog → M3 ---- */
#push-overlay { background: var(--scrim); z-index: 10040; }
.push-modal { background: var(--surface-container-high); border: none; border-radius: 28px; box-shadow: var(--shadow-3); }
.push-title { font-family: var(--font-display); font-weight: 600; color: var(--on-surface); }
.push-count { font-family: var(--font-display); color: var(--primary); font-weight: 600; }
.push-bar { background: var(--surface-container-highest); border: none; height: 8px; }
.push-bar-fill { background: var(--primary); }

/* ---- Snackbar → M3 (inverse surface) ---- */
#snackbar { background: var(--inverse-surface); color: var(--inverse-on-surface); border: none; border-radius: var(--radius); box-shadow: var(--shadow-3); font-weight: 500; }

@media (max-width: 720px) { .topbar { padding: 10px 14px; } .content { padding: 24px 16px 64px; } .topnav { gap: 0; } .topnav a { padding: 8px; font-size: 12.5px; } }

/* ======================================================================
   M3 REFINEMENTS · ROUND 2  (audit fixes from screenshots)
   Fieldset/legend badges, key/value spacing, M3 selects, tables, status
   chips, networks + bidding surfaces, existing-groups overlap. CSS only.
   ====================================================================== */
/* key/value rows — stop label + long value jamming together */
.kv { gap: 16px; align-items: baseline; border-bottom-color: var(--outline-variant); }
.kv span { color: var(--on-surface-variant); white-space: nowrap; }
.kv b { color: var(--on-surface); text-align: right; }

/* Builder steps → M3 filled cards + numbered section headers */
.builder-step { background: var(--surface-container-low); border: 1px solid var(--outline-variant); border-radius: var(--radius-lg); box-shadow: var(--shadow-1); padding: 20px 22px; }
.builder-step legend { display: inline-flex; align-items: center; gap: 10px; padding: 0; margin-bottom: 8px; color: var(--on-surface); font-family: var(--font-body); font-size: 13px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; }
.builder-step legend .num { display: inline-grid; place-items: center; width: 24px; height: 24px; border-radius: 50%; background: var(--primary); color: var(--on-primary); font-size: 11.5px; font-weight: 600; margin: 0; letter-spacing: 0; }
.preview-panel { background: var(--surface-container-low); border: 1px solid var(--outline-variant); border-radius: var(--radius-lg); box-shadow: var(--shadow-1); }

/* labels + radios */
.lbl { color: var(--on-surface-variant); font-size: 12px; font-weight: 500; letter-spacing: 0.02em; }
.radio-row label { color: var(--on-surface); }

/* Native selects → M3 filled field with a proper chevron */
select { appearance: none; -webkit-appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='%23888888' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 12px center; padding-right: 40px; }

/* Tables → M3 */
.table { background: var(--surface-container-low); border: 1px solid var(--outline-variant); box-shadow: var(--shadow-1); }
.table th { background: var(--surface-container); color: var(--on-surface-variant); font-family: var(--font-body); font-weight: 600; text-transform: none; letter-spacing: 0.02em; font-size: 12px; }
.table th, .table td { border-bottom-color: var(--outline-variant); }
.table td { color: var(--on-surface); }
.table tr:hover td { background: var(--fill-hover); }

/* Status chips → M3 tonal */
.status { border-radius: var(--radius-pill); font-family: var(--font-body); font-weight: 600; padding: 4px 12px; letter-spacing: 0.02em; font-size: 11px; text-transform: none; }
.status-draft { color: var(--on-surface-variant); background: var(--surface-container-highest); }
.status-generated, .status-enabled { color: var(--on-primary-container); background: var(--primary-container); }
.status-pushed, .status-pushed_partial { color: var(--success); background: rgba(var(--good-rgb),0.18); }
.status-disabled, .status-push_failed { color: var(--on-error-container); background: var(--error-container); }
.pill-android, .pill-ios { border-color: transparent; background: var(--secondary-container); color: var(--on-secondary-container); }

/* Networks page → M3 surfaces */
.net-app-list, .net-app-section { background: var(--surface-container-low); border: 1px solid var(--outline-variant); box-shadow: var(--shadow-1); }
.net-app-link { color: var(--on-surface-variant); border-radius: var(--radius); }
.net-app-link:hover { background: var(--fill-hover); color: var(--on-surface); }
.net-tabs { border-bottom-color: var(--outline-variant); }
.net-form { background: var(--surface-container); border: 1px solid var(--outline-variant); }
.net-unit-row { background: var(--surface-container-lowest); border: 1px solid var(--outline-variant); }
.net-tab-content h4, .net-form h4 { color: var(--on-surface); font-weight: 600; }

/* Bidding → M3 surfaces */
.bid-app-pick, .bid-step-card, .bid-confirm-card, .bid-existing-card, .bid-preview-card { background: var(--surface-container-low); border: 1px solid var(--outline-variant); box-shadow: var(--shadow-1); }
.bid-loaded-banner { background: var(--surface-container); border-color: var(--outline-variant); }
.bid-loaded-banner.has-saved { border-color: rgba(var(--good-rgb),0.4); }
.bid-net-form { background: var(--surface-container); border: 1px solid var(--outline-variant); }
.bid-net-form.is-on { border-color: var(--primary); background: rgba(var(--accent-rgb),0.05); }
.bid-fmt-section { background: var(--surface-container); border-color: var(--outline-variant); }
.bid-fmt-section > summary:hover { background: var(--fill-hover); }
.bid-net-grid input, .bid-net-grid select, .bid-app-label select { background: var(--surface-container-highest); border-color: var(--outline); color: var(--on-surface); }
.bid-net-name-big, .bid-step-head h3, .bid-existing-head h3, .bid-preview-head h3, .bid-fmt-label { color: var(--on-surface); }
.bid-step-head h3, .bid-existing-head h3, .bid-preview-head h3 { font-weight: 600; }
/* existing-groups row — fix long format names (REWARDED_INTERSTITIAL) overlapping the value */
.bid-existing-row { grid-template-columns: minmax(160px, max-content) 1fr; column-gap: 20px; background: var(--surface-container); border-color: var(--outline-variant); }
.bid-existing-row.has-groups { border-color: rgba(var(--good-rgb),0.4); }
.bid-existing-fmt { white-space: nowrap; color: var(--on-surface); }
.bid-section-badge, .bid-count { background: var(--surface-container-highest); color: var(--on-surface-variant); border-color: transparent; }
.bid-count.is-on { background: var(--primary-container); color: var(--on-primary-container); border-color: transparent; }
.bid-db-info code, .bid-loaded-pill.bid-loaded-empty { background: var(--surface-container-highest); }
.bid-loaded-pill { background: rgba(var(--good-rgb),0.16); color: var(--success); border-color: transparent; }
.bid-confirm { background: rgba(var(--accent-rgb),0.06); border-color: rgba(var(--accent-rgb),0.28); }
.bid-preview-json, .calc-explainer, .forensic-block { background: var(--surface-container-highest); border-color: var(--outline-variant); color: var(--on-surface-variant); }

/* metric + report + line-table surfaces */
.metric { background: var(--surface-container); border-color: var(--outline-variant); }
.report-card { background: var(--surface-container-low); border-color: var(--outline-variant); box-shadow: var(--shadow-1); }
.line-table, .line-table-head, .line-table-row { border-color: var(--outline-variant); }
.line-table-head { background: var(--surface-container); color: var(--on-surface-variant); }
.empty { background: var(--surface-container-low); border-color: var(--outline-variant); }

/* ======================================================================
   DASHBOARD · account dropdown + charts (M3)
   ====================================================================== */
.grid-4 { grid-template-columns: repeat(4, 1fr); }
@media (max-width: 900px) { .grid-4 { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 520px) { .grid-4 { grid-template-columns: 1fr; } }
.stat-row { margin-bottom: 18px; }
.acct-card { margin: 0 0 20px; }
.acct-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 12px; }
.acct-single { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }

/* M3 dropdown menu (details/summary popover) */
.m3-menu { position: relative; }
.m3-menu > summary { list-style: none; cursor: pointer; }
.m3-menu > summary::-webkit-details-marker { display: none; }
.m3-menu-btn { display: inline-flex; align-items: center; gap: 10px; min-width: 200px; justify-content: space-between; padding: 10px 16px; border-radius: var(--radius-pill); border: 1px solid var(--outline); background: var(--surface-container-highest); color: var(--on-surface); font-size: 14px; font-weight: 500; }
.m3-menu-btn:hover { background: var(--surface-container-high); }
.m3-menu[open] .chev { transform: rotate(180deg); }
.m3-menu .chev { transition: transform .15s ease; color: var(--on-surface-variant); }
.m3-menu-list { position: absolute; right: 0; top: calc(100% + 6px); z-index: 30; width: 300px; max-width: 86vw; background: var(--surface-container-high); border: 1px solid var(--outline-variant); border-radius: 12px; box-shadow: var(--shadow-3); padding: 10px; max-height: 340px; overflow-y: auto; }
.m3-menu-list input[type="text"] { width: 100%; margin-bottom: 8px; }
.m3-menu-item { display: flex; align-items: center; gap: 12px; padding: 10px 10px; border-radius: 8px; cursor: pointer; font-size: 13.5px; color: var(--on-surface); }
.m3-menu-item:hover { background: var(--fill-hover); }
.m3-menu-item input { accent-color: var(--primary); width: 16px; height: 16px; }
.m3-menu-item > span:nth-child(2) { flex: 1; font-family: var(--font-mono); font-size: 12.5px; }

/* Bar charts */
.dash-charts { margin: 4px 0 24px; align-items: start; }
.chart-card { padding: 20px 22px; }
.bar-chart { display: flex; flex-direction: column; gap: 12px; margin-top: 14px; }
.bar-row { display: grid; grid-template-columns: 130px 1fr 34px; align-items: center; gap: 12px; }
.bar-label { font-size: 12.5px; color: var(--on-surface-variant); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bar-track { height: 10px; background: var(--surface-container-highest); border-radius: var(--radius-pill); overflow: hidden; }
.bar-fill { display: block; height: 100%; background: var(--primary); border-radius: var(--radius-pill); transition: width .4s ease; min-width: 4px; }
.bar-val { font-size: 13px; font-weight: 600; color: var(--on-surface); text-align: right; font-variant-numeric: tabular-nums; }

/* Push status split bar */
.status-split { display: flex; gap: 4px; height: 26px; margin-top: 12px; }
.split-seg { display: grid; place-items: center; border-radius: 6px; min-width: 26px; color: #fff; font-size: 12px; font-weight: 600; }
.split-seg:only-child, .split-seg span { pointer-events: none; }
.split-pushed { background: var(--success); }
.split-draft { background: var(--surface-container-highest); color: var(--on-surface-variant); }
.split-seg[style*="flex:0"] { display: none; }
.split-legend { display: flex; gap: 18px; margin-top: 10px; font-size: 12.5px; color: var(--on-surface-variant); }
.dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 4px; }
.dot-pushed { background: var(--success); }
.dot-draft { background: var(--outline); }

/* ======================================================================
   M3 form controls — checkboxes, radios, correct color-scheme
   ====================================================================== */
:root[data-theme="light"] { color-scheme: light; }
:root[data-theme="dark"] { color-scheme: dark; }
input[type="checkbox"], input[type="radio"] { accent-color: var(--primary); width: 18px; height: 18px; cursor: pointer; flex: none; }
/* labels that wrap a checkbox/radio must lay out in a ROW (the global
   `label{flex-direction:column}` was stacking the box above its text) */
label:has(> input[type="checkbox"]), label:has(> input[type="radio"]) { flex-direction: row; align-items: center; gap: 10px; }
.bid-confirm { align-items: flex-start; }
/* table checkboxes stay centered in their cell */
.table td input[type="checkbox"] { margin: 0; }

/* ======================================================================
   M3 tables — vertical alignment, sane wrapping, tidy headers
   ====================================================================== */
.table { table-layout: auto; }
.table th, .table td { vertical-align: middle; }
.table th { white-space: nowrap; }
.table td { word-break: normal; overflow-wrap: anywhere; }
/* long monospace IDs (app id / store id / ad unit id) wrap cleanly instead
   of forcing a column to blow up and squash the others */
.table td.mono, .table .mono { word-break: break-all; font-size: 12.5px; color: var(--on-surface-variant); }
/* the trailing action link ("Open →", "Manage →") never wraps */
.table td:last-child { white-space: nowrap; }
.table td:last-child a { white-space: nowrap; }
.table tr td { line-height: 1.45; }

/* headings — a touch more air above the title so the overline isn't cramped */
.page-head { margin-bottom: 30px; }
.page-head .eyebrow { margin-bottom: 10px; }
.content { padding-top: 40px; }
.row-between.page-head { align-items: flex-start; }

/* Builder step header — plain div (previously a fieldset legend that pierced
   the card's top border). Card border now stays fully intact. */
.builder-legend { display: flex; align-items: center; gap: 10px; margin: 0 0 16px; color: var(--on-surface); font-family: var(--font-body); font-size: 13px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; }
"""


def write_assets() -> None:
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    for name, body in TEMPLATE_FILES.items():
        (TEMPLATES_DIR / name).write_text(body, encoding="utf-8")
    (STATIC_DIR / "style.css").write_text(CSS_CONTENT, encoding="utf-8")


# ============================================================================
# AUTO-MIGRATIONS (SQLite only)
# ============================================================================
def _auto_migrate_sqlite() -> None:
    if not settings.database_url.startswith("sqlite"):
        return
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy.exc import OperationalError

    sql_type_map = {
        "INTEGER": "INTEGER", "VARCHAR": "TEXT", "TEXT": "TEXT",
        "FLOAT": "REAL", "REAL": "REAL", "BOOLEAN": "INTEGER",
        "DATETIME": "TEXT", "JSON": "TEXT",
    }
    with engine.connect() as conn:
        insp = sa_inspect(conn)
        existing_tables = set(insp.get_table_names())
        for table_name, table in Base.metadata.tables.items():
            if table_name not in existing_tables:
                continue
            existing_columns = {c["name"] for c in insp.get_columns(table_name)}
            for col in table.columns:
                if col.name in existing_columns:
                    continue
                py_type_name = str(col.type).upper().split("(")[0]
                sql_type = sql_type_map.get(py_type_name, "TEXT")
                default_clause = ""
                default_val = col.default.arg if col.default is not None and not callable(getattr(col.default, "arg", None)) else None
                if isinstance(default_val, bool):
                    default_clause = f" DEFAULT {1 if default_val else 0}"
                elif isinstance(default_val, (int, float)):
                    default_clause = f" DEFAULT {default_val}"
                elif isinstance(default_val, str):
                    safe = default_val.replace("'", "''")
                    default_clause = f" DEFAULT '{safe}'"
                stmt = f'ALTER TABLE "{table_name}" ADD COLUMN "{col.name}" {sql_type}{default_clause}'
                try:
                    conn.exec_driver_sql(stmt)
                    print(f"  [migrate] {table_name}: + {col.name} {sql_type}")
                except OperationalError as e:
                    print(f"  [migrate] FAILED on {table_name}.{col.name}: {e}")
        conn.commit()


# ============================================================================
# APP
# ============================================================================
write_assets()
Base.metadata.create_all(bind=engine)
_auto_migrate_sqlite()


BUILD_TAG = "waterfall-v1alpha-batchcreate-v13-aes256-security"

# ============================================================================
# VERSION + CHANGELOG  (shown in the footer; click the version for details)
# ============================================================================
APP_VERSION = "1.3.2"
CHANGELOG = [
    {
        "version": "1.3.2",
        "date": "2026-07-13",
        "title": "Critical fix: eCPM / revenue now in USD (matches AdMob)",
        "changes": [
            "Fixed a major reporting bug: the AdMob API returns earnings and eCPM "
            "in the account's LOCAL currency (e.g. UAE Dirham) unless a currency "
            "is requested. The tool was reading those values as US dollars, which "
            "inflated every eCPM and revenue figure by the exchange rate "
            "(AED = 3.6725, so numbers were ~3.67x too high).",
            "The report now explicitly requests USD, so eCPM, revenue, and RPM "
            "match the AdMob dashboard exactly (e.g. $3.44 -> $0.94).",
            "IMPORTANT: waterfalls created before this fix used the inflated base "
            "eCPM, so their tier floors were ~3.67x too high. Re-fetch the report "
            "and re-push those groups to get correct USD-based floors.",
        ],
    },
    {
        "version": "1.3.1",
        "date": "2026-07-13",
        "title": "Fix: returning users seeing the old cached page",
        "changes": [
            "Fixed a caching problem where users who had opened the tool before "
            "the redesign could still see the OLD interface (and its old numbers) "
            "because their browser or the Cloudflare edge was serving a stale copy "
            "of the page.",
            "HTML pages are now always re-fetched fresh (no-store), and the "
            "stylesheet is versioned per release, so an update is picked up "
            "immediately — no more mismatched old UI or stale eCPM values.",
            "Note: the eCPM the server calculates was already correct (AdMob "
            "Mediation 'Observed eCPM'); the old figure some users saw came only "
            "from a cached old page, not from a wrong calculation.",
        ],
    },
    {
        "version": "1.3",
        "date": "2026-07-13",
        "title": "Material 3 redesign — cleaner, clearer, easier",
        "changes": [
            "Complete visual overhaul built on Google's Material 3 (Material You) "
            "design system — a cleaner, more modern, and more consistent interface "
            "across every screen.",
            "Light and dark mode: a new theme toggle (🌙 / ☀️) in the top bar lets "
            "you switch instantly. Your choice is remembered on this device, and the "
            "app opens in light mode by default.",
            "New professional-blue colour theme with proper Material tonal surfaces, "
            "so buttons, selected states, and highlights all feel consistent.",
            "Cards are now clean, white, elevated surfaces that float above a softly "
            "tinted background — content is much easier to scan.",
            "Refreshed typography using Google's Roboto font for a crisp, readable "
            "look throughout.",
            "The sign-in screen now shows the official multi-colour Google logo on "
            "the 'Continue with Google' button.",
            "Redesigned Dashboard with at-a-glance charts: mediation groups by "
            "format, apps by platform, and a push-status bar (how many groups are "
            "live in AdMob vs. still draft), plus a new 'Ad units' count card.",
            "Multiple AdMob accounts are now handled with a clean dropdown menu "
            "(search + checkboxes) instead of a row of chips — pick which accounts' "
            "apps appear in the Builder.",
            "All on-screen text rewritten in plain, friendly English — long, "
            "technical descriptions replaced with short, easy-to-understand wording "
            "on the login, dashboard, builder, networks, bidding, and cleanup pages.",
            "Buttons, form fields, dropdowns, checkboxes, radio buttons, dialogs, "
            "tables, and status chips all restyled to Material 3 standards.",
            "Pop-up confirmations replaced with clean Material dialogs (no more "
            "plain browser alerts).",
            "Bidding network keys and IDs (App Key, SDK Key) are now shown as plain "
            "text instead of hidden dots, so you can read and verify them.",
            "Many layout fixes: table columns and text now align correctly, long IDs "
            "wrap cleanly, section headings no longer overlap card borders, and the "
            "selected-app label reads clearly.",
            "No change to how mediation groups, tier ad units, or bidding mappings "
            "are created in AdMob — this release is purely about the look, wording, "
            "and ease of use.",
        ],
    },
    {
        "version": "1.2",
        "date": "2026-07-07",
        "title": "Waterfall tuning, more countries",
        "changes": [
            "Waterfall eCPM multipliers updated: V1 ×5.5 (top) → V10 ×0.85 (bottom).",
            "Country list expanded to 140 — added Kuwait, Morocco, Oman, Azerbaijan, "
            "Tanzania, Myanmar and many more (Middle East, Africa, Asia, Europe, LatAm).",
            "Group-name prefix now auto-fills from the selected country (US, US_GB, …).",
            "Max eCPM clamp ($1000) enforced on both the UI and the server before push.",
            "Low-eCPM ad units: when the 7-day average is below the $0.20 floor, "
            "the floor is used as the base so tiers keep a proper spread "
            "(V1 $1.10 … V10 $0.20) instead of collapsing to a flat $0.20.",
            "Builder: click ANYWHERE on an ad-unit card to select it (not just "
            "the button); selected ad units are listed in the Live Preview panel "
            "and can be removed from there.",
            "Push speed: multi-group pushes now pre-create ALL tier ad units and "
            "ALL bidding mappings in a few batched AdMob calls (~70% fewer API "
            "round-trips) — a 12-group push makes ~16 calls instead of ~48. "
            "If a batch fails, those groups automatically fall back to the "
            "previous per-group calls.",
        ],
    },
    {
        "version": "1.1",
        "date": "2026-06-29",
        "title": "Accurate eCPM, faster & safer",
        "changes": [
            "eCPM now uses AdMob's Mediation 'Observed eCPM' (matches the AdMob UI) "
            "with a Mediation/Network toggle.",
            "Report window fixed to the last 7 COMPLETE days (excludes today).",
            "Country-wise reports return real per-geo values.",
            "Push runs as a background job with a live progress bar + count + snackbar — "
            "no more request time-outs on large pushes.",
            "Database made persistent & self-healing across deploys (no data loss).",
            "Tool renamed to “Flow”.",
        ],
    },
    {
        "version": "1.0",
        "date": "2026-06-12",
        "title": "Initial release",
        "changes": [
            "AdMob mediation waterfall builder: tier ad units + one group per source.",
            "Country-wise reports, AdMob account selector, cleanup screen.",
            "Bidding network mappings, live audit.",
            "AES-256-GCM encryption of stored tokens & credentials; Google OAuth.",
        ],
    },
]

# Values that must never be used as a real secret.
_WEAK_SECRETS = {"", "change-me-in-env", "secret", "changeme", "password"}


def _enforce_secret_key() -> None:
    """secret_key signs sessions AND derives the AES-256 key for every stored
    token. A weak/default value would let anyone forge sessions and (with DB
    access) decrypt credentials. Refuse to start in production; warn in dev."""
    sk = (settings.secret_key or "").strip()
    weak = sk in _WEAK_SECRETS or len(sk) < 16
    if not weak:
        return
    msg = ("INSECURE secret_key: set a strong random value (>=32 chars) via the "
           "SECRET_KEY env var. Generate one with:  "
           "python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
    if settings.debug:
        _log(f"  ⚠ WARNING — {msg}")
    else:
        raise RuntimeError(msg)


@asynccontextmanager
async def lifespan(_: "FastAPI"):
    _enforce_secret_key()
    url = f"http://localhost:{settings.port}"
    try:
        mtime = datetime.fromtimestamp(
            Path(__file__).stat().st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        mtime = "?"
    log_abs = str(_LOG_FILE.resolve())
    longest = max(len(url), len(log_abs)) + 30
    bar = "=" * longest
    print(flush=True)
    print(bar, flush=True)
    print(f"  >>  Open in browser:    {url}", flush=True)
    print(f"  >>  flow.py build:      {BUILD_TAG}", flush=True)
    print(f"  >>  flow.py modified:   {mtime}", flush=True)
    print(bar, flush=True)
    print(f"  >>  LIVE LOG FILE: {log_abs}", flush=True)
    print(f"  >>  Tail it in another PowerShell window with:", flush=True)
    print(f"  >>    Get-Content '{log_abs}' -Wait -Tail 50", flush=True)
    print(bar, flush=True)
    print(flush=True)
    _log(f"server ready (build={BUILD_TAG}, mtime={mtime})")
    # Surface the DB location + whether it already holds data, so an empty /
    # non-persistent database is obvious at a glance (instead of silently
    # looking like "the data disappeared" after a redeploy without a volume).
    try:
        _dbf = make_url(settings.database_url).database if _is_sqlite else "(remote DB)"
        _s = SessionLocal()
        try:
            _u = _s.query(User).count(); _a = _s.query(AdMobApp).count()
        finally:
            _s.close()
        _log(f"database: {_dbf}  ->  {_u} user(s), {_a} app(s) cached")
        if _is_sqlite and _dbf and "/app/data" not in _dbf and "data" not in os.path.basename(os.path.dirname(_dbf or '.')):
            _log("  NOTE: SQLite is NOT under a 'data/' volume dir — mount one "
                 "(-v ./data:/app/data) so data survives container redeploys.")
    except Exception as _e:
        _log(f"  warning: DB status check failed ({_e})")
    _log(f"log file: {log_abs}")
    _log("when you click push in the browser, step-by-step logs will appear here AND in flow.log")
    yield


# NOTE: keep FastAPI's `debug` flag OFF even when settings.debug is True.
# When debug=True, Starlette's ServerErrorMiddleware intercepts unhandled
# exceptions and returns a plain-text traceback BEFORE our custom
# `_unhandled_to_json` handler can run — which makes the browser's
# fetch().json() blow up with "Unexpected token 'T', Traceback ...".
# Our handler below already prints the full traceback to the server console,
# so we're not losing any debug info.
app = FastAPI(title="Flow", debug=False, lifespan=lifespan)
# same_site="lax" lets the session cookie survive the Google -> /auth/callback
# top-level redirect. The cookie is always HttpOnly (JS can't read it) and is
# signed with secret_key. In production set cookie_secure=true so it is only
# ever sent over HTTPS; keep false for http://localhost dev.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    max_age=60 * 60 * 24 * 7,
    same_site="lax",
    https_only=settings.cookie_secure,
)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    """Defense-in-depth response headers on every response."""
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"               # anti-clickjacking
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    # CSP: block external/injected scripts & framing. 'unsafe-inline' is kept
    # because the templates rely on inline <style>/<script>; everything else is
    # locked to same-origin (plus Google avatars in <img>).
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    # HSTS only matters over HTTPS (production).
    if settings.cookie_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Never let a browser / Cloudflare edge serve a STALE HTML page. The page
    # markup carries the inline JS that renders reports and computes waterfall
    # eCPMs, so a cached old page would show old UI AND old numbers. Forcing a
    # revalidate on every HTML response guarantees returning users always get
    # the current code. (Static CSS/JS are versioned via ?v=<app_version>.)
    ctype = resp.headers.get("content-type", "")
    if ctype.startswith("text/html"):
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
# Expose the app version to every template (used in the footer link).
app.state.templates.env.globals["app_version"] = APP_VERSION


# ============================================================================
# GLOBAL JSON ERROR HANDLERS
# Make sure every error response is JSON so the builder's fetch().json()
# never chokes on an HTML traceback page with "Unexpected token T".
# Also log the full traceback to the server console for debugging.
# ============================================================================
import traceback as _tb_mod
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException


@app.exception_handler(StarletteHTTPException)
async def _http_exc_to_json(request: Request, exc: StarletteHTTPException):
    # Builder POST endpoints expect JSON; redirect-style HTML pages would
    # break the UI. We keep HTML for normal GET routes by checking Accept.
    accept = (request.headers.get("accept") or "").lower()
    wants_html = "text/html" in accept and request.method.upper() == "GET"
    if wants_html:
        # Fall back to default HTML behavior for HTML page requests
        from fastapi.responses import HTMLResponse as _H
        return _H(content=f"<h1>{exc.status_code}</h1><p>{exc.detail}</p>",
                  status_code=exc.status_code)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "status_code": exc.status_code},
    )


@app.exception_handler(RequestValidationError)
async def _validation_exc_to_json(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation failed", "errors": exc.errors()},
    )


@app.exception_handler(Exception)
async def _unhandled_to_json(request: Request, exc: Exception):
    # ALWAYS return JSON, even if our own logging fails. The old version
    # called _log() which writes to a file; if that file write somehow
    # raised, the handler itself crashed and Starlette fell back to the
    # plain "Internal Server Error" response that breaks the frontend's
    # fetch().json() call.
    try:
        tb = _tb_mod.format_exc()
    except Exception:
        tb = ""
    try:
        path = f"{request.method} {request.url.path}"
    except Exception:
        path = "<unknown>"
    try:
        _log(f"=== UNHANDLED EXCEPTION  {path} ===")
        for ln in tb.splitlines():
            _log(f"  {ln}")
        _log("=" * 50)
    except Exception:
        pass
    short_tb = ""
    try:
        lines = tb.strip().splitlines()
        short_tb = "\n".join(lines[-8:])
    except Exception:
        pass
    detail = "Internal error"
    try:
        detail = f"{type(exc).__name__}: {exc}"
    except Exception:
        pass
    return JSONResponse(
        status_code=500,
        content={"detail": detail, "traceback_tail": short_tb, "path": path},
    )



def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not signed in")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Session invalid; sign in again")
    return user


def tmpl(request: Request) -> Jinja2Templates:
    return request.app.state.templates


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard")
    return tmpl(request).TemplateResponse("login.html", {"request": request})


# ============================================================================
# AUTH ROUTES
# ============================================================================
auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.get("/login")
def login(request: Request):
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(status_code=500, detail="Google OAuth not configured.")
    auth_url, state, code_verifier = get_authorization_url()
    request.session["oauth_state"] = state
    request.session["code_verifier"] = code_verifier
    return RedirectResponse(auth_url)


@auth_router.get("/callback")
def callback(request: Request, code: str | None = None, state: str | None = None,
             error: str | None = None, db: Session = Depends(get_db)):
    # If Google bounced the user back with an explicit error param, surface it.
    if error:
        raise HTTPException(status_code=400, detail=f"Google OAuth error: {error}")
    expected_state = request.session.get("oauth_state")
    if not code:
        raise HTTPException(status_code=400, detail="OAuth callback missing authorization code.")
    if not state:
        raise HTTPException(status_code=400, detail="OAuth callback missing state parameter.")
    if not expected_state:
        # The session cookie didn't make it back. Almost always a hostname or
        # SameSite issue. Tell the user what to check rather than a generic 400.
        raise HTTPException(
            status_code=400,
            detail=(
                "OAuth session expired or cookie missing. Make sure you reach the "
                "app on the same host as the OAuth redirect URI "
                f"({settings.google_redirect_uri}). If you opened the app on "
                "127.0.0.1 but the redirect URI uses localhost (or vice versa) "
                "the session cookie is dropped."
            ),
        )
    if state != expected_state:
        raise HTTPException(status_code=400, detail="OAuth state mismatch (possible CSRF or stale session).")
    flow = build_flow(state=state)
    code_verifier = request.session.get("code_verifier")
    if code_verifier:
        flow.code_verifier = code_verifier
    try:
        flow.fetch_token(code=code)
    except Exception as e:
        # Surface the real reason (invalid_grant, redirect_uri_mismatch,
        # Warning: Scope has changed, etc.) instead of a generic 500.
        raise HTTPException(
            status_code=400,
            detail=f"Failed to exchange auth code for token: {type(e).__name__}: {e}",
        )
    creds = flow.credentials
    profile = requests.get(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {creds.token}"}, timeout=15,
    ).json()
    sub = profile.get("sub")
    email = profile.get("email", "")
    if not sub:
        raise HTTPException(status_code=500, detail="Could not read Google profile.")
    user = db.query(User).filter(User.google_sub == sub).first()
    if user is None:
        user = User(google_sub=sub, email=email, name=profile.get("name", ""),
                    picture=profile.get("picture", ""),
                    admob_publisher_id=settings.admob_publisher_id or "")
        db.add(user); db.commit(); db.refresh(user)
    else:
        user.email = email
        user.name = profile.get("name", user.name)
        user.picture = profile.get("picture", user.picture)
        db.commit()
    persist_credentials(db, user, creds)
    request.session.update({"user_id": user.id, "user_email": user.email,
                            "user_name": user.name, "user_picture": user.picture})
    request.session.pop("oauth_state", None)
    request.session.pop("code_verifier", None)
    return RedirectResponse("/dashboard")


@auth_router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")


# ============================================================================
# DASHBOARD
# ============================================================================
dash_router = APIRouter(tags=["dashboard"])


@dash_router.get("/changelog", response_class=HTMLResponse)
def changelog_view(request: Request, db: Session = Depends(get_db)):
    # Public (no login required) so the footer "vX.Y" link works everywhere.
    # Still resolve the user if signed in, so the nav bar stays consistent.
    user = None
    uid = request.session.get("user_id")
    if uid:
        user = db.query(User).filter(User.id == uid).first()
    return tmpl(request).TemplateResponse(
        "changelog.html",
        {"request": request, "user": user, "changelog": CHANGELOG},
    )


@dash_router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    publisher_id = user.admob_publisher_id
    api_error = None
    if not publisher_id:
        try:
            publisher_id = AdMobClient(db, user).get_publisher_id()
        except AdMobAPIError as e:
            api_error = str(e)
    apps = db.query(AdMobApp).filter(AdMobApp.user_id == user.id).all()
    app_count = len(apps)
    groups = db.query(MediationGroup).filter(MediationGroup.user_id == user.id).all()
    group_count = len(groups)
    accounts = _accounts_from_apps(apps)

    # ---- Lightweight stats for the dashboard charts (computed from cache) ----
    from collections import Counter
    plat_counts = Counter((a.platform or "OTHER").upper() for a in apps)
    fmt_counts = Counter((g.ad_format or "OTHER").upper() for g in groups)
    status_counts = Counter((g.status or "DRAFT").upper() for g in groups)
    adunit_count = sum(len(a.ad_units) for a in apps)
    pushed = status_counts.get("PUSHED", 0) + status_counts.get("PUSHED_PARTIAL", 0)

    def _bars(counter, order=None):
        items = ([(k, counter.get(k, 0)) for k in order if counter.get(k, 0)]
                 if order else sorted(counter.items(), key=lambda x: -x[1]))
        top = max([v for _, v in items], default=0)
        return [{"label": k, "value": v,
                 "pct": round(100 * v / top) if top else 0} for k, v in items]

    stats = {
        "platforms": _bars(plat_counts),
        "formats": _bars(fmt_counts, order=[
            "BANNER", "INTERSTITIAL", "REWARDED", "REWARDED_INTERSTITIAL",
            "NATIVE", "APP_OPEN"]),
        "adunit_count": adunit_count,
        "pushed": pushed,
        "draft": group_count - pushed,
    }
    return tmpl(request).TemplateResponse("dashboard.html", {
        "request": request, "user": user,
        "publisher_id": publisher_id or "(not detected - click Sync Apps)",
        "app_count": app_count, "group_count": group_count, "api_error": api_error,
        "accounts": accounts, "stats": stats,
        "max_lines": WATERFALL_MAX_LINES,
    })


# ============================================================================
# APPS ROUTES
# ============================================================================
apps_router = APIRouter(prefix="/apps", tags=["apps"])


@apps_router.get("", response_class=HTMLResponse)
def list_apps_view(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    apps = db.query(AdMobApp).filter(AdMobApp.user_id == user.id).all()
    return tmpl(request).TemplateResponse("apps.html", {"request": request, "user": user, "apps": apps})


def _publisher_of_app_id(app_id: str) -> str:
    """Derive the publisher id from an AdMob appId/adUnitId.

    `ca-app-pub-7823379550491034~2664862870` -> `pub-7823379550491034`
    (works for ad unit ids `ca-app-pub-XXXX/YYYY` too). Used to scope sync to
    a single AdMob account so other accounts' cached data is left intact."""
    if "pub-" in app_id:
        return "pub-" + app_id.split("pub-", 1)[1].split("~")[0].split("/")[0]
    return ""


def _accounts_from_apps(apps) -> list[dict]:
    """Distinct AdMob accounts (publishers) present in the user's cached apps,
    each with its app count. Drives the account selector on the dashboard and
    builder. Sorted by publisher id for a stable order."""
    counts: dict[str, int] = {}
    for a in apps:
        pub = _publisher_of_app_id(a.app_id) or "unknown"
        counts[pub] = counts.get(pub, 0) + 1
    return [{"publisher": p, "app_count": c} for p, c in sorted(counts.items())]


@apps_router.post("/sync")
def sync_apps(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        client = AdMobClient(db, user)
        current_pub = client.get_publisher_id()
        api_apps = client.list_apps()
        api_ad_units = client.list_ad_units()
    except AdMobAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))
    existing = {a.app_id: a for a in db.query(AdMobApp).filter(AdMobApp.user_id == user.id).all()}
    now = datetime.utcnow()
    api_app_ids = {a.get("appId", "") for a in api_apps if a.get("appId")}
    # ACCOUNT-SCOPED sync. The AdMob API only ever returns the publisher the
    # user most recently signed into from the AdMob UI (accounts.list returns
    # exactly that one). So we ONLY refresh apps belonging to `current_pub`,
    # and leave apps from OTHER AdMob accounts the user has cached untouched —
    # a user whose email can access several AdMob accounts keeps each one's
    # data. We purge only CURRENT-account apps that AdMob no longer returns.
    stale = [a for app_id, a in existing.items()
             if _publisher_of_app_id(app_id) == current_pub and app_id not in api_app_ids]
    for app_row in stale:
        db.delete(app_row)
    if stale:
        db.commit()
        existing = {a.app_id: a for a in db.query(AdMobApp).filter(AdMobApp.user_id == user.id).all()}
    for api_app in api_apps:
        admob_id = api_app.get("appId", "")
        platform = api_app.get("platform", "ANDROID")
        details = api_app.get("manualAppInfo") or api_app.get("linkedAppInfo") or {}
        name = details.get("displayName", "") or api_app.get("name", "")
        pkg = (api_app.get("linkedAppInfo") or {}).get("appStoreId", "")
        row = existing.get(admob_id)
        if row is None:
            db.add(AdMobApp(user_id=user.id, app_id=admob_id, name=name,
                            platform=platform, package_name=pkg, last_synced_at=now))
        else:
            row.name = name or row.name
            row.platform = platform
            row.package_name = pkg or row.package_name
            row.last_synced_at = now
    db.commit()
    db_apps = {a.app_id: a for a in db.query(AdMobApp).filter(AdMobApp.user_id == user.id).all()}
    # Refresh ad units ONLY for the current account's apps; other accounts'
    # ad units stay as they were.
    current_app_pks = [a.id for app_id, a in db_apps.items()
                       if _publisher_of_app_id(app_id) == current_pub]
    if current_app_pks:
        db.query(AdUnit).filter(AdUnit.app_id.in_(current_app_pks)).delete(synchronize_session=False)
    for unit in api_ad_units:
        parent = db_apps.get(unit.get("appId", ""))
        if parent is None:
            continue
        db.add(AdUnit(app_id=parent.id, ad_unit_id=unit.get("adUnitId", ""),
                      name=unit.get("displayName", "") or unit.get("name", ""),
                      ad_format=unit.get("adFormat", "BANNER"), last_synced_at=now))
    db.commit()
    # Cache the AdMob-side mediation groups too, so the Cleanup screen can
    # list them instantly from the DB (sync once, browse fast). Account-scoped:
    # only the current publisher's cached groups are refreshed. A failure here
    # must not fail the whole sync — apps/ad units are already committed.
    try:
        api_groups = client.list_mediation_groups_in_admob()
    except AdMobAPIError:
        api_groups = None
    if api_groups is not None:
        db.query(AdMobMediationGroupCache).filter(
            AdMobMediationGroupCache.user_id == user.id,
            AdMobMediationGroupCache.publisher_id == current_pub,
        ).delete(synchronize_session=False)
        for g in api_groups:
            db.add(AdMobMediationGroupCache(
                user_id=user.id, publisher_id=current_pub,
                group_id=g.get("mediation_group_id", ""),
                display_name=g.get("display_name", ""),
                platform=g.get("platform", ""),
                ad_format=g.get("format", ""),
                state=g.get("state", ""),
                ad_unit_ids=g.get("ad_unit_ids", []) or [],
                line_count=g.get("line_count", 0),
                last_synced_at=now,
            ))
        db.commit()
    return RedirectResponse("/apps", status_code=303)


@apps_router.get("/{db_app_id}", response_class=HTMLResponse)
def app_detail(db_app_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    app_row = db.query(AdMobApp).filter(AdMobApp.id == db_app_id, AdMobApp.user_id == user.id).first()
    if not app_row:
        raise HTTPException(status_code=404, detail="App not found")
    return tmpl(request).TemplateResponse("app_detail.html", {
        "request": request, "user": user, "app": app_row, "ad_units": app_row.ad_units,
    })


# ============================================================================
# NETWORKS ROUTES
# ============================================================================
networks_router = APIRouter(prefix="/networks", tags=["networks"])


@networks_router.get("", response_class=HTMLResponse)
def networks_view(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    apps = db.query(AdMobApp).filter(AdMobApp.user_id == user.id).order_by(AdMobApp.name).all()
    app_creds: dict[tuple, dict] = {}
    for c in db.query(NetworkCredential).filter(NetworkCredential.user_id == user.id).all():
        app_creds[(c.app_id, c.network_code)] = decrypt_dict(c.encrypted_fields)
    unit_creds: dict[tuple, dict] = {}
    for m in db.query(AdUnitMapping).filter(AdUnitMapping.user_id == user.id).all():
        unit_creds[(m.app_id, m.ad_unit_id, m.network_code)] = {
            "fields": decrypt_dict(m.encrypted_fields),
            "admob_mapping_id": m.admob_mapping_id,
        }
    return tmpl(request).TemplateResponse("networks.html", {
        "request": request, "user": user,
        "apps": apps,
        "networks": [n for n in NETWORK_CATALOG if not n.get("internal_only")],
        "app_creds_by_app_net": app_creds,
        "unit_creds_by_key": unit_creds,
    })


@networks_router.post("/{app_pk}/{network_code}/save-app")
async def save_app_creds(
    app_pk: int, network_code: str, request: Request,
    db: Session = Depends(get_db), user: User = Depends(current_user),
):
    cat = NETWORK_BY_CODE.get(network_code.upper())
    if not cat:
        raise HTTPException(status_code=404, detail="Unknown network")
    app_row = db.query(AdMobApp).filter(AdMobApp.id == app_pk, AdMobApp.user_id == user.id).first()
    if not app_row:
        raise HTTPException(status_code=404, detail="App not found")
    form = await request.form()
    fields = {f["key"]: (form.get(f["key"]) or "").strip() for f in cat["app_fields"]}
    cred = db.query(NetworkCredential).filter(
        NetworkCredential.user_id == user.id,
        NetworkCredential.app_id == app_pk,
        NetworkCredential.network_code == cat["code"],
    ).first()
    if cred is None:
        cred = NetworkCredential(user_id=user.id, app_id=app_pk, network_code=cat["code"])
        db.add(cred)
    cred.encrypted_fields = encrypt_dict(fields)
    db.commit()
    return RedirectResponse(f"/networks#app-{app_pk}", status_code=303)


@networks_router.post("/{app_pk}/{network_code}/save-unit/{ad_unit_id:path}")
async def save_unit_creds(
    app_pk: int, network_code: str, ad_unit_id: str, request: Request,
    db: Session = Depends(get_db), user: User = Depends(current_user),
):
    cat = NETWORK_BY_CODE.get(network_code.upper())
    if not cat:
        raise HTTPException(status_code=404, detail="Unknown network")
    app_row = db.query(AdMobApp).filter(AdMobApp.id == app_pk, AdMobApp.user_id == user.id).first()
    if not app_row:
        raise HTTPException(status_code=404, detail="App not found")
    form = await request.form()
    fields = {f["key"]: (form.get(f["key"]) or "").strip() for f in cat["ad_unit_fields"]}
    mp = db.query(AdUnitMapping).filter(
        AdUnitMapping.user_id == user.id,
        AdUnitMapping.app_id == app_pk,
        AdUnitMapping.ad_unit_id == ad_unit_id,
        AdUnitMapping.network_code == cat["code"],
    ).first()
    has_value = any(fields.values())
    if mp is None and has_value:
        mp = AdUnitMapping(user_id=user.id, app_id=app_pk, ad_unit_id=ad_unit_id, network_code=cat["code"])
        db.add(mp)
    if mp is not None:
        existing = decrypt_dict(mp.encrypted_fields) if mp.encrypted_fields else {}
        if existing != fields:
            mp.admob_mapping_id = ""
            mp.admob_mapping_name = ""
        mp.encrypted_fields = encrypt_dict(fields)
        if not has_value and mp.id:
            db.delete(mp)
    db.commit()
    return RedirectResponse(f"/networks#app-{app_pk}", status_code=303)


# ============================================================================
# BIDDING ROUTES — per-(app, network, ad_unit_id) bidding mappings. Same UI
# pattern as /networks but with an "enabled" toggle per ad-unit row. At
# mediation-group push time, each enabled row becomes a real AdUnitMapping
# on the source ad unit + a LIVE bidding line on the group (only when the
# builder's "Include All Bidding Networks" toggle is on; default ON).
# ============================================================================
bidding_router = APIRouter(prefix="/bidding", tags=["bidding"])


def _bidding_networks() -> list[dict]:
    """3P networks that are eligible for bidding (skips AdMob Network)."""
    return [n for n in NETWORK_CATALOG
            if n.get("supports_bidding") and not n.get("internal_only")]


@bidding_router.get("", response_class=HTMLResponse)
def bidding_view(request: Request, db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    apps = db.query(AdMobApp).filter(
        AdMobApp.user_id == user.id).order_by(AdMobApp.name).all()
    # (app_id, network_code, ad_format) -> {enabled, ad_unit_id, fields}
    mappings: dict[tuple, dict] = {}
    for m in db.query(BiddingFormatMapping).filter(
            BiddingFormatMapping.user_id == user.id).all():
        mappings[(m.app_id, m.network_code, m.ad_format)] = {
            "enabled": bool(m.enabled),
            "ad_unit_id": m.ad_unit_id or "",
            "fields": decrypt_dict(m.encrypted_fields),
        }
    # Group each app's ad units by format so the template can render a
    # format-filtered dropdown without doing the work itself.
    units_by_app_format: dict[tuple, list[dict]] = {}
    for a in apps:
        for u in a.ad_units:
            key = (a.id, (u.ad_format or "").upper())
            units_by_app_format.setdefault(key, []).append({
                "ad_unit_id": u.ad_unit_id, "name": u.name or u.ad_unit_id,
            })
    # Per-app summary: how many bidding configs saved + most recent update
    saved_summary: dict[int, dict] = {}
    for a in apps:
        count = enabled = 0
        latest: datetime | None = None
        for m in db.query(BiddingFormatMapping).filter(
                BiddingFormatMapping.user_id == user.id,
                BiddingFormatMapping.app_id == a.id).all():
            count += 1
            if m.enabled:
                enabled += 1
            if latest is None or (m.updated_at and m.updated_at > latest):
                latest = m.updated_at
        saved_summary[a.id] = {
            "count": count, "enabled": enabled,
            "updated": latest.strftime("%Y-%m-%d %H:%M") if latest else "",
        }
    return tmpl(request).TemplateResponse("bidding.html", {
        "request": request, "user": user,
        "apps": apps,
        "networks": _bidding_networks(),
        "formats": BIDDING_FORMATS,
        "mappings": mappings,
        "units_by_app_format": units_by_app_format,
        "saved_summary": saved_summary,
        "db_url": settings.database_url,
    })


@bidding_router.get("/{app_pk}/check-groups")
def check_mediation_groups(
    app_pk: int, db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Auto-check AdMob for existing mediation groups targeting THIS app's
    ad units, grouped by ad format. Returns "Mediation group not found"
    semantics per-format (empty list) so the UI can show that exactly."""
    app_row = db.query(AdMobApp).filter(
        AdMobApp.id == app_pk, AdMobApp.user_id == user.id).first()
    if not app_row:
        raise HTTPException(status_code=404, detail="App not found")
    app_unit_ids = {u.ad_unit_id for u in app_row.ad_units}
    by_format: dict[str, list[dict]] = {fmt: [] for fmt in BIDDING_FORMATS}
    if not app_unit_ids:
        return {"by_format": by_format, "total_ad_units": 0}
    try:
        client = AdMobClient(db, user)
        groups = client.list_mediation_groups_in_admob()
    except AdMobAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))
    # AdMob returns the format as "APP_OPEN_AD"; map back to our "APP_OPEN".
    fmt_back = {"APP_OPEN_AD": "APP_OPEN"}
    for g in groups:
        gau_ids = set(g.get("ad_unit_ids", []) or [])
        if not (gau_ids & app_unit_ids):
            continue
        fmt_raw = (g.get("format") or "").upper()
        fmt = fmt_back.get(fmt_raw, fmt_raw)
        if fmt not in by_format:
            continue
        by_format[fmt].append({
            "id": g.get("mediation_group_id"),
            "name": g.get("display_name") or "(unnamed)",
            "state": g.get("state"),
            "line_count": g.get("line_count", 0),
        })
    return {"by_format": by_format, "total_ad_units": len(app_unit_ids)}


@bidding_router.post("/{app_pk}/save-all")
async def save_all_bidding(
    app_pk: int, payload: dict = Body(...),
    db: Session = Depends(get_db), user: User = Depends(current_user),
):
    """ADFLUX-style bulk save — accepts every (network, format) row for an
    app in one request and upserts BiddingFormatMapping rows. Payload:
        {"mappings": [
            {"network": "META", "format": "BANNER", "enabled": true,
             "ad_unit_id": "ca-app-pub-XXX/YYY",
             "fields": {"placement_id": "..."}},
            ...
        ]}
    """
    app_row = db.query(AdMobApp).filter(
        AdMobApp.id == app_pk, AdMobApp.user_id == user.id).first()
    if not app_row:
        raise HTTPException(status_code=404, detail="App not found")
    items = payload.get("mappings") or []
    saved = enabled_count = 0
    for item in items:
        net_code = str(item.get("network") or "").upper()
        ad_fmt = str(item.get("format") or "").upper()
        cat = NETWORK_BY_CODE.get(net_code)
        if not cat or not cat.get("supports_bidding"):
            continue
        if ad_fmt not in BIDDING_FORMATS:
            continue
        is_enabled = bool(item.get("enabled"))
        ad_unit_id = (item.get("ad_unit_id") or "").strip()
        valid_keys = [f["key"] for f in (cat.get("app_fields") or [])] + \
                     [f["key"] for f in (cat.get("ad_unit_fields") or [])]
        raw_fields = item.get("fields") or {}
        fields = {k: (raw_fields.get(k) or "").strip() for k in valid_keys}
        row = db.query(BiddingFormatMapping).filter(
            BiddingFormatMapping.user_id == user.id,
            BiddingFormatMapping.app_id == app_pk,
            BiddingFormatMapping.network_code == net_code,
            BiddingFormatMapping.ad_format == ad_fmt,
        ).first()
        if row is None:
            row = BiddingFormatMapping(
                user_id=user.id, app_id=app_pk,
                network_code=net_code, ad_format=ad_fmt)
            db.add(row)
        row.ad_unit_id = ad_unit_id
        row.encrypted_fields = encrypt_dict(fields)
        row.enabled = is_enabled
        saved += 1
        if is_enabled:
            enabled_count += 1
    db.commit()
    return {"status": "ok", "saved": saved, "enabled": enabled_count}


@bidding_router.post("/{app_pk}/{network_code}/{ad_format}/save")
async def save_bidding_format(
    app_pk: int, network_code: str, ad_format: str, request: Request,
    db: Session = Depends(get_db), user: User = Depends(current_user),
):
    cat = NETWORK_BY_CODE.get(network_code.upper())
    if not cat or not cat.get("supports_bidding"):
        raise HTTPException(status_code=404, detail="Unknown bidding network")
    if ad_format.upper() not in BIDDING_FORMATS:
        raise HTTPException(status_code=400, detail="Invalid ad_format")
    app_row = db.query(AdMobApp).filter(
        AdMobApp.id == app_pk, AdMobApp.user_id == user.id).first()
    if not app_row:
        raise HTTPException(status_code=404, detail="App not found")
    form = await request.form()
    enabled = (form.get("enabled") or "").lower() in ("on", "true", "1", "yes")
    ad_unit_id = (form.get("ad_unit_id") or "").strip()
    all_field_keys = [f["key"] for f in (cat.get("app_fields") or [])] + \
                     [f["key"] for f in (cat.get("ad_unit_fields") or [])]
    fields = {k: (form.get(k) or "").strip() for k in all_field_keys}
    row = db.query(BiddingFormatMapping).filter(
        BiddingFormatMapping.user_id == user.id,
        BiddingFormatMapping.app_id == app_pk,
        BiddingFormatMapping.network_code == cat["code"],
        BiddingFormatMapping.ad_format == ad_format.upper(),
    ).first()
    if row is None:
        row = BiddingFormatMapping(
            user_id=user.id, app_id=app_pk,
            network_code=cat["code"], ad_format=ad_format.upper())
        db.add(row)
    row.ad_unit_id = ad_unit_id
    row.encrypted_fields = encrypt_dict(fields)
    row.enabled = enabled
    db.commit()
    return RedirectResponse(
        f"/bidding#app-{app_pk}", status_code=303)


# ============================================================================
# MEDIATION ROUTES
# ============================================================================
med_router = APIRouter(prefix="/mediation", tags=["mediation"])


@med_router.get("", response_class=HTMLResponse)
def list_groups(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    groups = db.query(MediationGroup).filter(MediationGroup.user_id == user.id).order_by(MediationGroup.updated_at.desc()).all()
    return tmpl(request).TemplateResponse("mediation_list.html", {"request": request, "user": user, "groups": groups})


@med_router.get("/builder", response_class=HTMLResponse)
def builder_view(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    apps = db.query(AdMobApp).filter(AdMobApp.user_id == user.id).order_by(AdMobApp.name).all()
    ad_units_by_app: dict[int, list[dict]] = {}
    for a in apps:
        ad_units_by_app[a.id] = [
            {"id": u.id, "ad_unit_id": u.ad_unit_id, "name": u.name, "ad_format": u.ad_format}
            for u in a.ad_units
        ]
    existing_groups: dict[str, list[dict]] = {}
    for g in db.query(MediationGroup).filter(MediationGroup.user_id == user.id).order_by(MediationGroup.created_at.desc()).all():
        if not g.target_ad_unit_id:
            continue
        existing_groups.setdefault(g.target_ad_unit_id, []).append({
            "id": g.id, "name": g.name, "status": g.status,
            "admob_group_id": g.admob_group_id or "",
            "created_at": g.created_at.strftime("%Y-%m-%d %H:%M") if g.created_at else "",
        })

    # Apps grouped by AdMob account (publisher) so the builder can offer an
    # account selector + per-account app filtering. The publisher is derived
    # from each app's id (no schema change). Note: the AdMob API only ever
    # returns ONE account at a time, but cached apps can span several accounts
    # the user has synced — those are what the selector lists.
    all_apps = [
        {"id": a.id, "name": a.name, "app_id": a.app_id,
         "platform": a.platform,
         "publisher": _publisher_of_app_id(a.app_id) or "unknown"}
        for a in apps
    ]
    accounts = _accounts_from_apps(apps)

    return tmpl(request).TemplateResponse("mediation_builder.html", {
        "request": request, "user": user, "apps": apps,
        "all_apps": all_apps, "accounts": accounts,
        "ad_units_by_app": ad_units_by_app,
        "countries": COMMON_COUNTRIES,
        "max_lines": WATERFALL_MAX_LINES,
        "default_lines": WATERFALL_DEFAULT_LINES,
        "floor_types": FLOOR_TYPES,
        "tier_multipliers": WATERFALL_TIER_MULTIPLIERS,
        "min_ecpm": WATERFALL_MIN_ECPM,
        "max_ecpm": WATERFALL_MAX_ECPM,
        "existing_groups": existing_groups,
    })


@med_router.post("/builder/fetch-report")
def builder_fetch_report(payload: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    ad_unit_ids = payload.get("ad_unit_ids") or []
    if not ad_unit_ids:
        raise HTTPException(status_code=400, detail="No ad unit IDs supplied")
    # Scope the report to the chosen geo. Only INCLUDE mode (specific countries)
    # narrows the report; GLOBAL stays worldwide, and EXCLUDE can't be expressed
    # by the AdMob report filter (match-any only), so it also stays global.
    country_mode = (payload.get("country_mode") or "GLOBAL").upper()
    raw_countries = [str(c).upper() for c in (payload.get("countries") or [])]
    countries = raw_countries if (country_mode == "INCLUDE" and raw_countries) else []
    # Last 7 COMPLETE days, ending YESTERDAY — NOT including today. Today is an
    # incomplete day (data still accumulating) and AdMob's UI "Last 7 days"
    # likewise excludes it. Including today previously skewed eCPM and shifted
    # the window by one day vs what AdMob shows (e.g. 23-29 instead of 22-28).
    start, end = _days_ago_iso(7), _days_ago_iso(1)
    # eCPM source toggle: "mediation" (default, matches AdMob UI) or "network".
    report_type = "network" if str(payload.get("report_type") or "").lower() == "network" else "mediation"
    try:
        client = AdMobClient(db, user)
        report = client.fetch_network_report_for_ad_units(
            ad_unit_ids, start, end, countries=countries, report_type=report_type)
    except AdMobAPIError as e:
        raise HTTPException(status_code=502, detail=str(e))
    for au in ad_unit_ids:
        report.setdefault(au, {
            "ad_requests": 0, "matched_requests": 0, "impressions": 0, "clicks": 0,
            "revenue_usd": 0.0, "ecpm_usd": 0.0, "rpm_usd": 0.0,
            "match_rate": 0.0, "show_rate": 0.0, "fill_rate": 0.0, "ctr": 0.0,
        })
    return {"start": start, "end": end, "report": report, "report_type": report_type,
            "countries": countries, "scope": "GLOBAL" if not countries else "COUNTRY"}


@med_router.post("/builder/generate")
def builder_generate(payload: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    # Saving a draft does NO AdMob calls, so it's fast — keep it synchronous.
    return _generate_groups(payload, db, user, push_to_admob=False)


# ---------------------------------------------------------------------------
# Background push jobs. Pushing to AdMob makes many sequential API calls and can
# run for minutes — longer than a reverse proxy / Cloudflare Tunnel's ~100s HTTP
# limit, which would otherwise return an HTML timeout page (the "Unexpected
# token '<'" error). So the push runs in a background thread and the browser
# polls a short status endpoint instead of holding one long request open.
_PUSH_JOBS: dict[str, dict] = {}
_PUSH_JOBS_LOCK = threading.Lock()


def _run_push_job(job_id: str, payload: dict, user_id: int) -> None:
    job_db = SessionLocal()
    try:
        job_user = job_db.query(User).filter(User.id == user_id).first()
        if job_user is None:
            raise RuntimeError("User not found for push job")

        def _progress(done: int, total: int, message: str) -> None:
            with _PUSH_JOBS_LOCK:
                cur = _PUSH_JOBS.get(job_id, {})
                cur.update({"status": "running", "done": done,
                            "total": total, "message": message})
                _PUSH_JOBS[job_id] = cur

        result = _generate_groups(payload, job_db, job_user,
                                  push_to_admob=True, progress=_progress)
        with _PUSH_JOBS_LOCK:
            _PUSH_JOBS[job_id] = {"status": "done", "result": result}
    except Exception as e:  # noqa: BLE001 — surface any failure to the poller
        import traceback
        traceback.print_exc()
        with _PUSH_JOBS_LOCK:
            _PUSH_JOBS[job_id] = {"status": "error", "error": str(e)}
    finally:
        job_db.close()


@med_router.post("/builder/push-to-admob")
def builder_push_to_admob(payload: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    job_id = uuid.uuid4().hex
    with _PUSH_JOBS_LOCK:
        # keep the table small — drop finished jobs once we have a lot
        if len(_PUSH_JOBS) > 50:
            for k in [k for k, v in _PUSH_JOBS.items() if v.get("status") != "running"][:40]:
                _PUSH_JOBS.pop(k, None)
        _PUSH_JOBS[job_id] = {"status": "running", "done": 0,
                              "total": len(payload.get("items") or []),
                              "message": "Starting…"}
    threading.Thread(target=_run_push_job, args=(job_id, payload, user.id),
                     daemon=True).start()
    return {"job_id": job_id, "status": "running"}


@med_router.get("/builder/push-status/{job_id}")
def builder_push_status(job_id: str, user: User = Depends(current_user)):
    with _PUSH_JOBS_LOCK:
        job = _PUSH_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Push job not found (it may have finished long ago — check /mediation)")
    return job


@med_router.post("/builder/fetch-admob-groups")
def builder_fetch_admob_groups(db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        client = AdMobClient(db, user)
        groups = client.list_mediation_groups_in_admob()
        return {"groups": groups}
    except AdMobAPIError as e:
        raise HTTPException(status_code=400, detail=str(e))


@med_router.post("/builder/push-to-existing")
def builder_push_to_existing(payload: dict = Body(...),
                              db: Session = Depends(get_db),
                              user: User = Depends(current_user)):
    group_id = str(payload.get("mediation_group_id") or "").strip()
    if not group_id:
        raise HTTPException(status_code=400, detail="mediation_group_id required")
    ecpms = [float(x) for x in (payload.get("ecpms") or []) if float(x) > 0]
    if not ecpms:
        raise HTTPException(status_code=400, detail="At least one positive eCPM required")
    display_name = str(payload.get("group_display_name") or f"Group {group_id}")
    try:
        client = AdMobClient(db, user)
        resp, lines_pushed = client.patch_lines_into_group(group_id, ecpms)
    except AdMobAPIError as e:
        return {
            "status": "failed", "error": str(e),
            "lines_requested": len(ecpms), "lines_pushed": 0,
        }
    local_group = MediationGroup(
        user_id=user.id,
        name=f"{display_name} (patched +{lines_pushed} lines)",
        ad_format="", platform="",
        status="PUSHED" if lines_pushed == len(ecpms) else "PUSHED_PARTIAL",
        country_mode="GLOBAL", countries=[],
        floor_type=FLOOR_TYPES[0],
        target_ad_unit_id="", target_ad_unit_name="",
        base_avg_ecpm=ecpms[0],
        report_metrics={},
        admob_group_id=group_id,
        admob_group_name=resp.get("name", "") or "",
        last_push_response=json.dumps(resp)[:4000],
    )
    db.add(local_group); db.commit(); db.refresh(local_group)
    for i, ecpm in enumerate(sorted(ecpms, reverse=True)[:lines_pushed]):
        db.add(WaterfallLine(
            group_id=local_group.id, priority=i,
            line_name=f"Line {i+1}", ecpm_usd=ecpm, enabled=True,
            network_code="ADMOB", cpm_mode="MANUAL",
        ))
    db.commit()
    return {
        "status": "ok" if lines_pushed == len(ecpms) else "partial",
        "lines_requested": len(ecpms),
        "lines_pushed": lines_pushed,
        "admob_group_id": group_id,
        "local_group_id": local_group.id,
    }


# ============================================================================
# Helper: ensure source ad unit has 3P bidding mappings created in AdMob
# ============================================================================
def _build_waterfall_lines_from_credentials(
    db: Session,
    client: "AdMobClient",
    user: User,
    app_row: "AdMobApp",
    source_ad_unit_id: str,
    ad_format: str,
    ecpms: list[float],
    push_errors: list[dict],
) -> tuple[list[dict], list[str]]:
    """Build MANUAL waterfall lines for the mediation group using the
    third-party networks the user saved credentials for on /networks.

    AdMob Network manual waterfall lines are not creatable via the API, so
    waterfall TIERS use 3rd-party networks (Meta / AppLovin / Unity /
    ironSource / Mintegral / Pangle). AdMob Network is added separately by
    the caller as the LIVE bidding line.

    For each network: combines app-level fields (NetworkCredential) with
    ad-unit-level fields (AdUnitMapping DB row), creates an AdUnitMapping
    on the source ad unit, and builds one MANUAL line. The computed eCPM
    tiers are assigned descending (highest eCPM = first network line).

    Returns (manual_line_dicts, network_names_used).
    """
    creds_rows = db.query(NetworkCredential).filter(
        NetworkCredential.user_id == user.id,
        NetworkCredential.app_id == app_row.id,
    ).all()
    # Fetch every AdUnitMapping row for this source ad unit once, indexed by
    # network_code — avoids a separate query per network credential below.
    unit_rows_by_code = {
        r.network_code: r
        for r in db.query(AdUnitMapping).filter(
            AdUnitMapping.user_id == user.id,
            AdUnitMapping.app_id == app_row.id,
            AdUnitMapping.ad_unit_id == source_ad_unit_id,
        ).all()
    }
    platform = (app_row.platform or "").upper()

    built: list[dict] = []
    pending = 0
    for cred in creds_rows:
        code = (cred.network_code or "").upper()
        cat = NETWORK_BY_CODE.get(code)
        if not cat or code == "ADMOB":
            continue

        app_fields = decrypt_dict(cred.encrypted_fields) if cred.encrypted_fields else {}
        unit_row = unit_rows_by_code.get(cred.network_code)
        unit_fields = (decrypt_dict(unit_row.encrypted_fields)
                       if unit_row and unit_row.encrypted_fields else {})
        user_fields = {**app_fields, **unit_fields}
        if not user_fields:
            _log(f"  {cat['name']}: no credentials saved — skipped")
            continue

        if pending > 0:
            # Light throttle between per-network source-mapping creates (the
            # quota-retry helper handles real saturation). Was 1.2s — lowered
            # to keep the push fast when several bidding networks are enabled.
            time.sleep(0.3)
        pending += 1

        suffix = source_ad_unit_id.split("/")[-1][-8:]
        display_name = f"{cat['name']} waterfall {suffix}"[:80]
        _log(f"  creating AdUnitMapping for {cat['name']} on source ad unit")
        try:
            resp, warnings = client.create_ad_unit_mapping_in_admob(
                ad_unit_id=source_ad_unit_id,
                network_code=code,
                platform=platform,
                display_name=display_name,
                user_fields=user_fields,
            )
        except AdMobAPIError as e:
            _log(f"     {cat['name']} mapping FAILED: {e}")
            push_errors.append({
                "ad_unit_id": source_ad_unit_id, "tier": "",
                "stage": f"create_mapping({code})", "error": str(e),
            })
            continue

        mapping_name = resp.get("name", "") or ""
        source_id = client.find_source_id_for_network(code)
        if not mapping_name or not source_id:
            push_errors.append({
                "ad_unit_id": source_ad_unit_id, "tier": "",
                "stage": f"create_mapping({code})",
                "error": "mapping created but missing name/source id",
            })
            continue
        built.append({
            "network_code": code, "network_name": cat["name"],
            "source_id": source_id, "mapping_name": mapping_name,
        })
        _log(f"     {cat['name']} mapping OK")

    # Assign eCPM tiers descending — highest eCPM to the first network line.
    sorted_ecpms = sorted([e for e in ecpms if e and e > 0], reverse=True)
    manual_lines: list[dict] = []
    names_used: list[str] = []
    for i, b in enumerate(built):
        if i < len(sorted_ecpms):
            ecpm = sorted_ecpms[i]
        elif sorted_ecpms:
            ecpm = sorted_ecpms[-1]
        else:
            ecpm = 0.20
        cpm_micros = int(round(ecpm * 1_000_000))
        manual_lines.append({
            "displayName": f"{b['network_name']} - ${ecpm:.2f}"[:80],
            "adSourceId": b["source_id"],
            "cpmMode": "MANUAL",
            "cpmMicros": str(cpm_micros),
            "state": "ENABLED",
            "adUnitMappings": {source_ad_unit_id: b["mapping_name"]},
        })
        names_used.append(b["network_name"])
    return manual_lines, names_used


# ============================================================================
# Core builder: per source ad unit, create tier ad units + one mediation group
# ============================================================================
def _generate_groups(payload: dict, db: Session, user: User, push_to_admob: bool,
                     progress=None):
    """For each selected source ad unit, build a real AdMob mediation group
    via the public v1alpha API:

      1. batchCreate N AdMob Network Waterfall backing ad units (one per
         tier eCPM). Each one comes back with an auto-created AdUnitMapping
         on the source ad unit — that mapping is the "pubid" piece the
         older internal-cURL hack used to fake.
      2. Create ONE mediation group targeting the source ad unit, with:
         - N MANUAL "AdMob Network Waterfall" lines (one per tier eCPM,
           each referencing its auto-created mapping)
         - 1 LIVE "AdMob Network" bidding line
      3. Persist locally (MediationGroup + WaterfallLine rows mirror what
         was actually pushed).
    """
    try:
        app_pk = int(payload.get("app_id") or 0)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid app_id")
    app_row = db.query(AdMobApp).filter(
        AdMobApp.id == app_pk, AdMobApp.user_id == user.id,
    ).first()
    if not app_row:
        raise HTTPException(status_code=404, detail="App not found")

    country_mode = (payload.get("country_mode") or "GLOBAL").upper()
    if country_mode not in ("GLOBAL", "INCLUDE", "EXCLUDE"):
        raise HTTPException(status_code=400, detail="Bad country_mode")
    countries = [str(c).upper() for c in (payload.get("countries") or [])]
    floor_type = payload.get("floor_type") or FLOOR_TYPES[0]
    if floor_type not in FLOOR_TYPES:
        raise HTTPException(status_code=400, detail="Bad floor_type")
    unique_names = bool(payload.get("unique_names"))
    name_prefix = (payload.get("name_prefix") or "Group").strip().replace(" ", "_")
    # Builder toggle: "Include All Bidding Networks" (default ON). When True,
    # _generate_groups adds LIVE bidding lines from saved /bidding mappings.
    include_bidding_networks = (
        True if payload.get("include_bidding_networks") is None
        else bool(payload.get("include_bidding_networks")))
    items = payload.get("items") or []
    if not items:
        raise HTTPException(status_code=400, detail="No ad units selected")

    overall_start = time.time()
    mode = "PUSH" if push_to_admob else "GENERATE (no AdMob writes)"
    _log(f"==== {mode} START — {len(items)} source ad unit(s) ====")

    if push_to_admob:
        _log("Initializing AdMob client (OAuth refresh if needed) ...")
    client = AdMobClient(db, user) if push_to_admob else None
    if push_to_admob:
        _log("AdMob client ready.")
    created: list[dict] = []
    push_errors: list[dict] = []
    push_countries = countries if country_mode == "INCLUDE" else []

    # ========================================================================
    # PRE-BATCH (speed): a push of many groups used to make 2+N AdMob calls
    # PER group, sequentially — 12 groups easily meant ~48 round-trips and
    # 10+ minutes once AdMob write latency/backoff stacked up. Here we create
    # ALL tier backing units and ALL bidding mappings up-front in a handful
    # of batchCreate calls; the per-group loop then only creates the group
    # itself (1 call each). Any pre-batch failure falls back to the original
    # per-group calls, so behaviour is unchanged when batching can't be used.
    # ========================================================================
    pre_specs: dict[str, list] = {}          # ad_unit_id -> tier_specs
    pre_tier_units: dict[str, list] = {}     # ad_unit_id -> backing units
    pre_bid_mappings: dict[tuple, str] = {}  # (ad_unit_id, network) -> name
    if push_to_admob and client is not None and len(items) > 1:
        valid = []
        for it in items:
            au = str(it.get("ad_unit_id") or "")
            ecs = [min(WATERFALL_MAX_ECPM, max(WATERFALL_MIN_ECPM, float(x)))
                   for x in (it.get("lines") or []) if float(x) > 0]
            if au and ecs:
                nm = str(it.get("ad_unit_name") or au)
                fmt = str(it.get("ad_format") or "BANNER")
                sorted_ecs = sorted(ecs, reverse=True)
                specs = [
                    (f"{nm}_tier{i}_${ec:.2f}".replace(" ", "_")[:80], ec)
                    for i, ec in enumerate(sorted_ecs, start=1)
                ]
                pre_specs[au] = specs
                valid.append({"app_id": app_row.app_id,
                              "primary_ad_unit_id": au,
                              "ad_format": fmt, "tiers": specs})
        # --- Phase A: all tier backing units in a few batch calls ---
        if valid:
            total_tiers = sum(len(v["tiers"]) for v in valid)
            if progress:
                progress(0, len(items),
                         f"Batch-creating {total_tiers} tier ad units for "
                         f"{len(valid)} group(s)…")
            _log(f"PRE-BATCH: creating {total_tiers} tier ad units for "
                 f"{len(valid)} group(s) in one pass")
            try:
                pre_tier_units, _failed = _timed(
                    "batch_create_waterfall_ad_units_multi",
                    lambda: client.batch_create_waterfall_ad_units_multi(valid),
                )
            except AdMobAPIError as e:
                _log(f"PRE-BATCH tier units failed entirely: {e} — "
                     f"falling back to per-group calls")
                pre_tier_units = {}
        # --- Phase B: all 3P bidding mappings in a few batch calls ---
        if include_bidding_networks and valid:
            bid_reqs: list[dict] = []
            fmt_items: dict[str, list[str]] = {}
            for v in valid:
                fmt_items.setdefault(v["ad_format"].upper(), []).append(
                    v["primary_ad_unit_id"])
            for fmt_key, au_list in fmt_items.items():
                rows = db.query(BiddingFormatMapping).filter(
                    BiddingFormatMapping.user_id == user.id,
                    BiddingFormatMapping.app_id == app_row.id,
                    BiddingFormatMapping.ad_format == fmt_key,
                    BiddingFormatMapping.enabled == True,
                ).all()
                for brow in rows:
                    cat = NETWORK_BY_CODE.get(brow.network_code)
                    if not cat:
                        continue
                    fields = (decrypt_dict(brow.encrypted_fields)
                              if brow.encrypted_fields else {})
                    if not any((v or "").strip() for v in fields.values()):
                        continue
                    try:
                        adapter_id, configs, _w = client.build_admob_config_payload(
                            network_code=brow.network_code,
                            platform=app_row.platform,
                            user_fields=fields, ad_format=fmt_key,
                            for_bidding=True,
                        )
                    except AdMobAPIError:
                        continue  # per-item fallback will surface the error
                    if not configs:
                        continue
                    for au in au_list:
                        bid_reqs.append({
                            "ad_unit_id": au,
                            "network_code": brow.network_code,
                            "adapter_id": adapter_id,
                            "configs": configs,
                            "display_name": (f"{cat['name']} bidding "
                                             f"{au.split('/')[-1][-6:]}"),
                        })
            if bid_reqs:
                if progress:
                    progress(0, len(items),
                             f"Batch-creating {len(bid_reqs)} bidding "
                             f"mapping(s)…")
                _log(f"PRE-BATCH: creating {len(bid_reqs)} bidding "
                     f"mapping(s) in one pass")
                try:
                    pre_bid_mappings = _timed(
                        "batch_create_bidding_mappings",
                        lambda: client.batch_create_bidding_mappings(bid_reqs),
                    )
                except AdMobAPIError as e:
                    _log(f"PRE-BATCH bidding mappings failed: {e} — "
                         f"falling back to per-item creates")
                    pre_bid_mappings = {}

    for item_idx, item in enumerate(items, start=1):
        ad_unit_id = str(item.get("ad_unit_id") or "")
        if not ad_unit_id:
            continue
        ad_unit_name = str(item.get("ad_unit_name") or ad_unit_id)
        ad_format = str(item.get("ad_format") or "BANNER")
        metrics = item.get("metrics") or {}
        # Server-side clamp — even if the UI sends out-of-range tier eCPMs,
        # AdMob rejects values outside [WATERFALL_MIN_ECPM, WATERFALL_MAX_ECPM].
        ecpms = [
            min(WATERFALL_MAX_ECPM, max(WATERFALL_MIN_ECPM, float(x)))
            for x in (item.get("lines") or []) if float(x) > 0
        ]
        if not ecpms:
            continue
        if progress:
            # done = items fully finished before this one; we're now starting
            # this one. Frontend renders bar + "done/total" + this message.
            progress(item_idx - 1, len(items),
                     f"Creating group {item_idx}/{len(items)}: {ad_unit_name}")
        _log(f"---- [{item_idx}/{len(items)}] source ad_unit={ad_unit_id} "
             f"name={ad_unit_name!r} tiers={len(ecpms)} ----")

        # ====================================================================
        # Build the mediation group:
        #   - Waterfall MANUAL lines  -> 3rd-party networks (from /networks
        #     credentials). AdMob Network manual waterfall lines are not
        #     API-creatable, so tiers use Meta / AppLovin / Unity / etc.
        #   - Bidding LIVE line       -> AdMob Network (always added).
        # All in ONE mediationGroups.create call, targeting the source ad
        # unit.
        # ====================================================================
        group_suffix = f"_{_random_suffix()}" if unique_names else ""
        group_display_name = (
            f"{name_prefix}_{ad_unit_name}{group_suffix}"
            .replace(" ", "_")[:80]
        )

        admob_group_id = ""
        admob_group_name = ""
        live_actual = 0
        manual_actual = 0
        group_error_log = ""
        waterfall_networks: list[str] = []

        if push_to_admob and client is not None:
            # Step 1 — batchCreate N AdMob Network Waterfall backing ad units
            # (v1alpha). Each returned unit carries an auto-created
            # AdUnitMapping on the source ad unit; that mapping is what the
            # MANUAL waterfall line references.
            sorted_ecpms = sorted([e for e in ecpms if e > 0], reverse=True)
            # Use the SAME tier specs the pre-batch phase used (order matters:
            # backing units are matched to tiers by position).
            tier_specs = pre_specs.get(ad_unit_id) or [
                (f"{ad_unit_name}_tier{i}_${ec:.2f}".replace(" ", "_")[:80], ec)
                for i, ec in enumerate(sorted_ecpms, start=1)
            ]
            if ad_unit_id in pre_tier_units:
                # Already created up-front in the multi-group batch.
                backing_units = pre_tier_units[ad_unit_id]
                _log(f"  using {len(backing_units)} pre-batched tier ad "
                     f"unit(s)")
            else:
                _log(f"  batchCreate {len(tier_specs)} AdMob Network Waterfall "
                     f"backing ad unit(s) [v1alpha]")
                try:
                    backing_units = _timed(
                        "batch_create_waterfall_ad_units",
                        lambda: client.batch_create_waterfall_ad_units(
                            app_id=app_row.app_id,
                            primary_ad_unit_id=ad_unit_id,
                            ad_format=ad_format,
                            tiers=tier_specs,
                        ),
                    )
                except AdMobAPIError as e:
                    _log(f"  batch_create_waterfall_ad_units FAILED: {e}")
                    push_errors.append({
                        "ad_unit_id": ad_unit_id, "tier": "",
                        "stage": "batch_create_waterfall_ad_units",
                        "error": str(e),
                    })
                    backing_units = []

            # Step 2 — build N MANUAL "AdMob Network Waterfall" lines, each
            # referencing its tier's auto-created mapping.
            try:
                waterfall_source_id = client.get_admob_waterfall_source_id()
            except AdMobAPIError:
                # Hardcoded fallback — stable cross-account constant.
                waterfall_source_id = "1215381445328257950"

            manual_lines = []
            waterfall_networks = []
            for (tier_name, ec), bu in zip(tier_specs, backing_units):
                mapping_name = (bu.get("mappingSetting", {}) or {}).get(
                    "adUnitMappingId", "")
                if not mapping_name:
                    push_errors.append({
                        "ad_unit_id": ad_unit_id, "tier": tier_name,
                        "stage": "missing_auto_mapping",
                        "error": "batchCreate returned no adUnitMappingId "
                                 "for this tier — fall back to "
                                 "accounts.adUnitMappings.batchCreate",
                    })
                    continue
                manual_lines.append({
                    "displayName": f"AdMob Waterfall ${ec:.2f}"[:255],
                    "adSourceId": waterfall_source_id,
                    "cpmMode": "MANUAL",
                    "cpmMicros": str(int(round(ec * 1_000_000))),
                    "state": "ENABLED",
                    "adUnitMappings": {ad_unit_id: mapping_name},
                })
                waterfall_networks.append(f"Tier_${ec:.2f}")
            _log(f"  built {len(manual_lines)} waterfall MANUAL line(s)")

            # Step 3 — AdMob Network LIVE bidding line, always present.
            try:
                admob_src_id = client.get_admob_network_source_id()
            except AdMobAPIError:
                admob_src_id = AdMobClient.ADMOB_NETWORK_SOURCE_ID
            bidding_lines = [{
                "displayName": "AdMob Network",
                "adSourceId": admob_src_id,
                "cpmMode": "LIVE",
                "state": "ENABLED",
            }]

            # Step 4 — 3P bidding LIVE lines from saved /bidding mappings
            # (when the builder's "Include All Bidding Networks" toggle is
            # on, default ON). For each enabled BiddingFormatMapping that
            # matches (this app, this ad_format) AND whose saved
            # `ad_unit_id` equals the source ad unit being pushed, create
            # a real AdUnitMapping on the source + add a LIVE bidding line.
            bidding_networks_added: list[str] = []
            if include_bidding_networks:
                fmt_key = (ad_format or "").upper()
                # NOTE: NO ad_unit_id filter here — saved bidding configs
                # apply to ANY source ad unit of the same (app, format).
                # The mapping creation below uses the SOURCE ad unit being
                # pushed (ad_unit_id), not the saved one. This matches the
                # user's requirement: "bidding har ad pa aaye".
                bidding_rows = db.query(BiddingFormatMapping).filter(
                    BiddingFormatMapping.user_id == user.id,
                    BiddingFormatMapping.app_id == app_row.id,
                    BiddingFormatMapping.ad_format == fmt_key,
                    BiddingFormatMapping.enabled == True,
                ).all()
                _log(f"  bidding: {len(bidding_rows)} enabled mapping(s) "
                     f"for format={fmt_key} on this app")
                for brow in bidding_rows:
                    cat = NETWORK_BY_CODE.get(brow.network_code)
                    if not cat:
                        continue
                    fields = (decrypt_dict(brow.encrypted_fields)
                              if brow.encrypted_fields else {})
                    if not any((v or "").strip() for v in fields.values()):
                        _log(f"    {cat['name']}: no field values saved — "
                             f"skipped")
                        continue
                    pre_name = pre_bid_mappings.get(
                        (ad_unit_id, brow.network_code))
                    if pre_name:
                        # Mapping was already created in the pre-batch phase.
                        mp_resp = {"name": pre_name}
                        _log(f"    {cat['name']}: using pre-batched mapping")
                    else:
                        dn = (f"{cat['name']} bidding "
                              f"{ad_unit_id.split('/')[-1][-6:]}")[:80]
                        try:
                            mp_resp, _warns = client.create_ad_unit_mapping_in_admob(
                                ad_unit_id=ad_unit_id,
                                network_code=brow.network_code,
                                platform=app_row.platform,
                                display_name=dn,
                                user_fields=fields,
                                ad_format=ad_format,
                                for_bidding=True,
                            )
                        except AdMobAPIError as e:
                            _log(f"    {cat['name']}: mapping create FAILED: {e}")
                            push_errors.append({
                                "ad_unit_id": ad_unit_id, "tier": "",
                                "stage": (f"create_bidding_mapping("
                                          f"{brow.network_code})"),
                                "error": str(e),
                            })
                            continue
                    mapping_name = (mp_resp or {}).get("name", "") or ""
                    # CRITICAL: use the BIDDING source id (not waterfall) for
                    # the LIVE bidding line. AdMob has a separate "(bidding)"
                    # ad source per network — using the waterfall source for
                    # LIVE lines triggers "CPM mode unsupported".
                    src_id = client.find_bidding_source_id_for_network(
                        brow.network_code)
                    if not src_id:
                        src_id = cat.get("admob_bidding_source_id") or cat.get("admob_source_id", "")
                    if not mapping_name or not src_id:
                        push_errors.append({
                            "ad_unit_id": ad_unit_id, "tier": "",
                            "stage": (f"create_bidding_mapping("
                                      f"{brow.network_code})"),
                            "error": ("mapping created but missing name or "
                                      "source id"),
                        })
                        continue
                    bidding_lines.append({
                        "displayName": f"{cat['name']} (bidding)"[:255],
                        "adSourceId": src_id,
                        "cpmMode": "LIVE",
                        "state": "ENABLED",
                        "adUnitMappings": {ad_unit_id: mapping_name},
                    })
                    bidding_networks_added.append(cat["name"])
                    _log(f"    + {cat['name']} LIVE bidding line ready")

            _log(f"Creating mediation group name={group_display_name!r} "
                 f"targeting {ad_unit_id} — "
                 f"{len(manual_lines)} waterfall line(s) + "
                 f"{len(bidding_lines)} bidding line(s) "
                 f"(AdMob Network + {', '.join(bidding_networks_added) or 'no 3P'})")
            try:
                mg_resp, manual_actual, live_actual, _m_req = _timed(
                    "create_mediation_group_in_admob",
                    lambda: client.create_mediation_group_in_admob(
                        display_name=group_display_name,
                        platform=app_row.platform,
                        ad_format=ad_format,
                        targeting_ad_unit_ids=[ad_unit_id],
                        country_codes=push_countries,
                        manual_lines=manual_lines,
                        bidding_lines=bidding_lines,
                    ),
                )
                admob_group_id = mg_resp.get("mediationGroupId", "") or ""
                admob_group_name = mg_resp.get("name", "") or ""
                _log(f"     group created id={admob_group_id} "
                     f"waterfall_lines={manual_actual} bidding_lines={live_actual}")
            except AdMobAPIError as e:
                _log(f"create_mediation_group FAILED: {e}")
                push_errors.append({
                    "ad_unit_id": ad_unit_id, "tier": "",
                    "stage": "create_mediation_group", "error": str(e),
                })
                group_error_log = f"[create_mediation_group] {e}"

        if not push_to_admob:
            group_status = "GENERATED"
        elif admob_group_id:
            group_status = "PUSHED"
        else:
            group_status = "PUSH_FAILED"

        api_response_summary = json.dumps({
            "admob_group_id": admob_group_id,
            "admob_group_name": admob_group_name,
            "waterfall_lines_in_group": manual_actual,
            "bidding_lines_in_group": live_actual,
            "waterfall_networks": waterfall_networks,
            "waterfall_tier_ecpms": ecpms,
        })[:4000]

        # ====================================================================
        # Persist locally.
        # ====================================================================
        group = MediationGroup(
            user_id=user.id,
            name=group_display_name,
            ad_format=ad_format,
            platform=app_row.platform,
            status=group_status,
            country_mode=country_mode,
            countries=countries,
            floor_type=floor_type,
            target_ad_unit_id=ad_unit_id,
            target_ad_unit_name=ad_unit_name,
            base_avg_ecpm=(metrics.get("ecpm_usd") or (ecpms[0] if ecpms else 0.0)),
            report_metrics=metrics,
            admob_group_id=admob_group_id,
            admob_group_name=admob_group_name,
            last_push_response=(api_response_summary or group_error_log)[:4000],
        )
        db.add(group); db.commit(); db.refresh(group)
        sorted_ecpms_save = sorted([e for e in ecpms if e and e > 0], reverse=True)
        line_pushed = bool(admob_group_id)
        for i, ecpm in enumerate(sorted_ecpms_save, start=1):
            db.add(WaterfallLine(
                group_id=group.id,
                priority=i - 1,
                line_name=f"AdMob Network Waterfall {i} — ${ecpm:.2f}",
                ecpm_usd=ecpm,
                enabled=line_pushed,
                network_code="ADMOB_WATERFALL",
                cpm_mode="MANUAL",
            ))
        db.add(WaterfallLine(
            group_id=group.id, priority=99,
            line_name="AdMob Network (bidding)",
            ecpm_usd=0.0, enabled=line_pushed,
            network_code="ADMOB", cpm_mode="LIVE",
        ))
        db.commit()

        created.append({
            "id": group.id,
            "name": group_display_name,
            "source_ad_unit_id": ad_unit_id,
            "admob_group_id": admob_group_id,
            "waterfall_lines_actual": manual_actual,
            "bidding_lines_actual": live_actual,
            "waterfall_networks": waterfall_networks,
            "waterfall_tier_ecpms": ecpms,
            "status": group_status,
        })
        _log(f"     item DONE status={group_status} "
             f"admob_group_id={admob_group_id or '-'} "
             f"waterfall_lines={manual_actual} bidding_lines={live_actual}")
        if progress:
            # Report AFTER this group is actually created, so the count ticks
            # up 1, 2, 3, ... exactly as each one finishes.
            progress(item_idx, len(items),
                     f"Created {item_idx}/{len(items)}: {ad_unit_name}")

    total_elapsed = time.time() - overall_start
    _log(f"==== {mode} DONE in {total_elapsed:.2f}s — "
         f"{len(created)} group plan(s), {len(push_errors)} error(s) ====")
    return {"status": "ok", "groups": created,
            "push_errors": push_errors, "pushed": push_to_admob}


@med_router.get("/{group_id}", response_class=HTMLResponse)
def show_group(group_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    group = db.query(MediationGroup).filter(MediationGroup.id == group_id, MediationGroup.user_id == user.id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return tmpl(request).TemplateResponse("mediation_detail.html", {"request": request, "user": user, "group": group})


@med_router.post("/{group_id}/delete")
def delete_group(group_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    group = db.query(MediationGroup).filter(MediationGroup.id == group_id, MediationGroup.user_id == user.id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    db.delete(group); db.commit()
    return RedirectResponse("/mediation", status_code=303)


@med_router.get("/{group_id}/export.json")
def export_group(group_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    group = db.query(MediationGroup).filter(MediationGroup.id == group_id, MediationGroup.user_id == user.id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return JSONResponse(AdMobClient(db, user).export_group_config(group))


# ============================================================================
# CLEANUP ROUTES — bulk-delete ad units & disable mediation groups
# ============================================================================
cleanup_router = APIRouter(prefix="/cleanup", tags=["cleanup"])


def _app_ad_unit_ids(db: Session, app_row: "AdMobApp") -> set[str]:
    """Full ad unit ids ('ca-app-pub-X/Y') cached for an app."""
    return {u.ad_unit_id for u in app_row.ad_units if u.ad_unit_id}


def _groups_for_app(db: Session, user: User, app_row: "AdMobApp") -> list:
    """Cached AdMob mediation groups that target any of this app's ad units.
    Falls back to a platform match for groups whose targeting ad units AdMob
    didn't return (rare)."""
    app_units = _app_ad_unit_ids(db, app_row)
    pub = _publisher_of_app_id(app_row.app_id)
    rows = db.query(AdMobMediationGroupCache).filter(
        AdMobMediationGroupCache.user_id == user.id,
        AdMobMediationGroupCache.publisher_id == pub,
    ).all()
    out = []
    for g in rows:
        gids = set(g.ad_unit_ids or [])
        if gids:
            if gids & app_units:
                out.append(g)
        elif g.platform and g.platform == (app_row.platform or ""):
            out.append(g)
    return out


@cleanup_router.get("", response_class=HTMLResponse)
def cleanup_view(request: Request, db: Session = Depends(get_db),
                 user: User = Depends(current_user)):
    apps = (db.query(AdMobApp).filter(AdMobApp.user_id == user.id)
            .order_by(AdMobApp.name).all())
    return tmpl(request).TemplateResponse("cleanup.html", {
        "request": request, "user": user, "apps": apps,
    })


@cleanup_router.get("/inventory/{app_db_id}")
def cleanup_inventory(app_db_id: int, db: Session = Depends(get_db),
                      user: User = Depends(current_user)):
    """Return the cached ad units + mediation groups for an app — straight
    from the DB, no AdMob call, so it's instant."""
    app_row = db.query(AdMobApp).filter(
        AdMobApp.id == app_db_id, AdMobApp.user_id == user.id).first()
    if not app_row:
        raise HTTPException(status_code=404, detail="App not found")
    ad_units = [
        {"ad_unit_id": u.ad_unit_id, "name": u.name or "(unnamed)",
         "ad_format": u.ad_format}
        for u in sorted(app_row.ad_units, key=lambda x: (x.ad_format or "", x.name or ""))
    ]
    groups = [
        {"group_id": g.group_id, "display_name": g.display_name or "(unnamed)",
         "platform": g.platform, "ad_format": g.ad_format,
         "state": g.state, "line_count": g.line_count}
        for g in _groups_for_app(db, user, app_row)
    ]
    last_sync = app_row.last_synced_at.strftime("%Y-%m-%d %H:%M") if app_row.last_synced_at else ""
    return {
        "app": {"id": app_row.id, "name": app_row.name, "app_id": app_row.app_id,
                "platform": app_row.platform, "last_synced_at": last_sync},
        "ad_units": ad_units, "groups": groups,
    }


@cleanup_router.post("/delete")
def cleanup_delete(payload: dict = Body(...), db: Session = Depends(get_db),
                   user: User = Depends(current_user)):
    """Delete selected ad units (hard delete) and disable selected mediation
    groups (AdMob has no group hard-delete) for one app. Only ids that belong
    to the app's cached inventory are accepted — a client can't pass arbitrary
    ids. `dry_run` validates without mutating."""
    app_db_id = payload.get("app_db_id")
    req_unit_ids = [str(x) for x in (payload.get("ad_unit_ids") or [])]
    req_group_ids = [str(x) for x in (payload.get("group_ids") or [])]
    dry_run = bool(payload.get("dry_run"))
    app_row = db.query(AdMobApp).filter(
        AdMobApp.id == app_db_id, AdMobApp.user_id == user.id).first()
    if not app_row:
        raise HTTPException(status_code=404, detail="App not found")
    if not req_unit_ids and not req_group_ids:
        raise HTTPException(status_code=400, detail="Nothing selected")

    # Scope the request to ids that actually belong to this app's inventory.
    valid_units = _app_ad_unit_ids(db, app_row)
    unit_ids = [u for u in req_unit_ids if u in valid_units]
    valid_groups = {g.group_id: g for g in _groups_for_app(db, user, app_row)}
    group_ids = [gid for gid in req_group_ids if gid in valid_groups]

    result = {
        "dry_run": dry_run,
        "ad_units": {"requested": len(req_unit_ids), "deleted": 0, "error": None},
        "groups": {"requested": len(req_group_ids), "disabled": 0,
                   "failed": [], "error": None},
        "note": ("Mediation groups can't be hard-deleted via the AdMob API — "
                 "they are DISABLED (stop serving; re-enableable). Ad units "
                 "are permanently deleted."),
    }
    try:
        client = AdMobClient(db, user)
    except (AdMobAPIError, RuntimeError) as e:
        raise HTTPException(status_code=502, detail=str(e))

    # --- Ad units: hard delete via batchDelete ---
    if unit_ids:
        try:
            res = client.batch_delete_ad_units(unit_ids, dry_run=dry_run)
            result["ad_units"]["deleted"] = res.get("deleted", 0)
            if not dry_run:
                db.query(AdUnit).filter(
                    AdUnit.app_id == app_row.id,
                    AdUnit.ad_unit_id.in_(unit_ids),
                ).delete(synchronize_session=False)
                db.commit()
        except AdMobAPIError as e:
            result["ad_units"]["error"] = str(e)

    # --- Mediation groups: disable via patch (no hard delete in API) ---
    for gid in group_ids:
        if dry_run:
            result["groups"]["disabled"] += 1
            continue
        try:
            client.disable_mediation_group(gid)
            result["groups"]["disabled"] += 1
            cache_row = valid_groups.get(gid)
            if cache_row is not None:
                cache_row.state = "DISABLED"
            # Reflect the change on any locally-tracked copy of the group too.
            db.query(MediationGroup).filter(
                MediationGroup.user_id == user.id,
                MediationGroup.admob_group_id == gid,
            ).update({"status": "DISABLED"}, synchronize_session=False)
        except AdMobAPIError as e:
            result["groups"]["failed"].append({"group_id": gid, "error": str(e)})
    if group_ids and not dry_run:
        db.commit()

    result["status"] = "ok" if not (
        result["ad_units"]["error"] or result["groups"]["failed"]) else "partial"
    return result


app.include_router(auth_router)
app.include_router(dash_router)
app.include_router(apps_router)
app.include_router(networks_router)
app.include_router(bidding_router)
app.include_router(med_router)
app.include_router(cleanup_router)


def _free_port_if_stuck(port: int) -> None:
    """If `port` is held by a stale Python process from a previous server
    run, kill that process so we can bind. Avoids the WinError 10048
    "only one usage of each socket address" error when the user restarts
    immediately after Ctrl+C while a long-running request was in flight
    (the underlying process keeps the socket bound until the request's
    AdMob calls finish).

    Only kills python.exe — never touches other processes — so this is
    safe to run unconditionally on startup.
    """
    import socket
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", port))
        return  # port is free; nothing to do
    except OSError:
        pass
    finally:
        try:
            probe.close()
        except Exception:
            pass

    if os.name != "nt":
        print(f"[startup] Port {port} is in use. Free it manually and retry.")
        return

    import subprocess
    try:
        out = subprocess.check_output(
            ["netstat", "-ano", "-p", "TCP"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"[startup] Port {port} in use but couldn't run netstat: {e}")
        return

    pids: set[int] = set()
    needle = f":{port}"
    for line in out.splitlines():
        # Lines look like: TCP    127.0.0.1:8000   0.0.0.0:0   LISTENING   12345
        if needle not in line or "LISTENING" not in line.upper():
            continue
        # The local address column must end with :PORT (avoid matching
        # connections where the remote port happens to be the same).
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[1]
        if not local.endswith(f":{port}"):
            continue
        try:
            pids.add(int(parts[-1]))
        except ValueError:
            pass

    my_pid = os.getpid()
    killed_any = False
    for pid in pids:
        if pid == my_pid:
            continue
        # Confirm it's a python process before killing — never kill
        # something unrelated that happens to be on this port.
        try:
            info = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                text=True, stderr=subprocess.DEVNULL,
            )
        except Exception:
            info = ""
        if "python" not in info.lower():
            print(f"[startup] Port {port} held by non-python PID {pid}; "
                  "not killing. Free it manually if you want to use this port.")
            continue
        print(f"[startup] Port {port} held by stale python PID {pid} — killing.")
        try:
            subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                check=False, capture_output=True,
            )
            killed_any = True
        except Exception as e:
            print(f"[startup] Failed to kill PID {pid}: {e}")

    if killed_any:
        # Give Windows a moment to release the socket fully.
        time.sleep(1.0)


if __name__ == "__main__":
    # Auto-free port from a stale previous run before binding.
    _free_port_if_stuck(settings.port)

    # NOTE: uvicorn's `reload=True` spawns a watcher subprocess that, on
    # Windows + Python 3.13, re-imports the whole module via
    # multiprocessing.spawn. That re-import triggers SQLAlchemy's
    # `platform.win32_ver()` (a slow WMI query) and any Ctrl+C / startup
    # race during that window produces a giant traceback, even though the
    # main server has already started fine. We default to no-reload and
    # let it be opted in explicitly via UVICORN_RELOAD=1 — restart by hand
    # after code changes.
    reload_enabled = os.environ.get("UVICORN_RELOAD", "").lower() in ("1", "true", "yes")
    uvicorn.run(
        "flow:app",
        host=settings.host,
        port=settings.port,
        reload=reload_enabled,
    )