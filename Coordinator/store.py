"""
Persistent registry for the coordinator (SQLite).

Passwords and bearer tokens are stored as hashes. User bearer tokens also have
an encrypted copy so authorized dashboard users can retrieve them.
"""
import hashlib
import hmac
import ipaddress
import os
import secrets
import sqlite3
import threading
import time
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
import base64

DB_PATH = os.getenv("COORD_DB", "coordinator.db")
# Name of the environment variable, not a secret value.
TOKEN_ENCRYPTION_KEY_ENV = "COORD_TOKEN_ENCRYPTION_KEY"  # nosec B105
# Daily /fetch limit given to every new user token. Admins can change it per token afterwards.
DEFAULT_DAILY_FETCH_LIMIT = int(os.getenv("DEFAULT_DAILY_FETCH_LIMIT", "100"))
_TOKEN_KEY_CHECK = b"distributed-crawler-token-key-check-v1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents(
    agent_id TEXT PRIMARY KEY,
    label TEXT DEFAULT '',
    owner TEXT DEFAULT '',
    token_hash TEXT UNIQUE NOT NULL,
    encrypted_token TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL,
    last_connected REAL,
    last_disconnected REAL,
    last_seen REAL,
    egress_ip TEXT,
    platform TEXT,
    agent_version TEXT,
    jobs_ok INTEGER NOT NULL DEFAULT 0,
    jobs_failed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clients(
    client_id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL,
    last_used REAL,
    requests INTEGER NOT NULL DEFAULT 0,
    owner TEXT,
    location TEXT,
    encrypted_token TEXT
);
CREATE TABLE IF NOT EXISTS admins(
    username TEXT PRIMARY KEY,
    pw_hash TEXT NOT NULL,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    pw_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL,
    email TEXT
);
CREATE TABLE IF NOT EXISTS dashboard_sessions(
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    agent_id TEXT,
    event TEXT NOT NULL,
    detail TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS office_networks(
    cidr TEXT PRIMARY KEY,          -- single IP stored as /32 (or /128), or a range like 203.0.113.0/28
    label TEXT DEFAULT '',
    created_at REAL
);
CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fetch_sessions(
    session_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_used REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS password_reset_tokens(
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    username TEXT NOT NULL,
    client_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    success INTEGER NOT NULL,
    status_code INTEGER,
    agent_id TEXT,
    duration_sec REAL NOT NULL,
    error TEXT DEFAULT '',
    service TEXT NOT NULL DEFAULT 'unknown',
    domain TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_agent ON events(agent_id, ts);
CREATE INDEX IF NOT EXISTS ix_fetch_sessions_last_used ON fetch_sessions(last_used);
CREATE INDEX IF NOT EXISTS ix_fetch_sessions_agent ON fetch_sessions(agent_id);
CREATE INDEX IF NOT EXISTS ix_password_reset_username ON password_reset_tokens(username, created_at);
CREATE INDEX IF NOT EXISTS ix_usage_logs_ts ON usage_logs(ts);
CREATE INDEX IF NOT EXISTS ix_usage_logs_user_ts ON usage_logs(username, ts);
CREATE INDEX IF NOT EXISTS ix_usage_logs_url ON usage_logs(url);
"""

# --------------------------------------------------------------------------- migrations
# Complete, constant DDL statements keyed by column name. Nothing is interpolated into
# SQL at runtime, so no variable data can ever reach an ALTER TABLE statement.
_USAGE_LOG_MIGRATIONS = (
    ("service", "ALTER TABLE usage_logs ADD COLUMN service TEXT NOT NULL DEFAULT 'unknown'"),
    ("domain", "ALTER TABLE usage_logs ADD COLUMN domain TEXT NOT NULL DEFAULT ''"),
)
_CLIENT_MIGRATIONS = (
    ("owner", "ALTER TABLE clients ADD COLUMN owner TEXT"),
    ("location", "ALTER TABLE clients ADD COLUMN location TEXT"),
    ("encrypted_token", "ALTER TABLE clients ADD COLUMN encrypted_token TEXT"),
    # per-token daily /fetch limit; usage_count belongs to usage_day and resets lazily.
    # DEFAULT_DAILY_FETCH_LIMIT is already an int; int() keeps that guaranteed.
    ("daily_limit", ("ALTER TABLE clients ADD COLUMN daily_limit "
                    f"INTEGER NOT NULL DEFAULT {int(DEFAULT_DAILY_FETCH_LIMIT)}")),
    ("usage_day", "ALTER TABLE clients ADD COLUMN usage_day TEXT"),
    ("usage_count", "ALTER TABLE clients ADD COLUMN usage_count INTEGER NOT NULL DEFAULT 0"),
)

# --------------------------------------------------------------------------- query templates
# Constant templates. The only runtime substitutions are (a) a WHERE clause assembled
# from fixed literals by Store._usage_where(), and (b) an UPDATE column list checked
# against _AGENT_UPDATABLE_FIELDS. All values are always bound with "?".
_USAGE_LIST_SQL = {
    "ASC": ("SELECT id,ts,username,client_id,url,method,success,status_code,agent_id,"
            "duration_sec,error,service,domain FROM usage_logs {where} "
            "ORDER BY ts ASC,id ASC LIMIT ? OFFSET ?"),
    "DESC": ("SELECT id,ts,username,client_id,url,method,success,status_code,agent_id,"
             "duration_sec,error,service,domain FROM usage_logs {where} "
             "ORDER BY ts DESC,id DESC LIMIT ? OFFSET ?"),
}
_USAGE_COUNT_SQL = "SELECT COUNT(*) AS n FROM usage_logs {where}"
_USAGE_TOTALS_SQL = (
    "SELECT COUNT(*) AS requests,COALESCE(SUM(success),0) AS succeeded,"
    "COUNT(*)-COALESCE(SUM(success),0) AS failed,COUNT(DISTINCT url) AS unique_urls "
    "FROM usage_logs {where}"
)
_USAGE_DAYS_SQL = (
    "SELECT date(ts,'unixepoch') AS date,username,service,domain,COUNT(*) AS requests,"
    "COALESCE(SUM(success),0) AS succeeded,"
    "COUNT(*)-COALESCE(SUM(success),0) AS failed,COUNT(DISTINCT url) AS unique_urls "
    "FROM usage_logs {where} GROUP BY date(ts,'unixepoch'),username,service,domain "
    "ORDER BY date DESC,username,service,domain"
)
_TOUCH_AGENT_SQL = "UPDATE agents SET {cols} WHERE agent_id=?"

# Agent columns touch_agent() may set. Anything else is rejected, so caller-supplied
# keyword names can never become SQL. Trim/extend to match what your callers really use.
_AGENT_UPDATABLE_FIELDS = frozenset({
    "label", "owner", "enabled", "last_connected", "last_disconnected", "last_seen",
    "egress_ip", "platform", "agent_version", "jobs_ok", "jobs_failed",
})


def _fill(template: str, placeholder: str, fragment: str) -> str:
    """Insert a trusted, code-generated SQL fragment into a constant template.

    `template` is always one of the module-level constants above and `fragment` is only
    ever built from fixed literals or allowlisted column names (never from request data).
    This is the single place where SQL text is composed.
    """
    return template.replace(placeholder, fragment)  # nosec B608


# --------------------------------------------------------------------------- hashing
def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _fernet(key_hex: str) -> Fernet:
    raw = bytes.fromhex(key_hex)                      # 32 bytes
    return Fernet(base64.urlsafe_b64encode(raw))      # Fernet-compatible key


def encrypt(text: str, key_hex: str) -> str:
    return _fernet(key_hex).encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt(token: str, key_hex: str) -> str:
    try:
        return _fernet(key_hex).decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Invalid key or corrupted/tampered data")


def new_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, dk_hex = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calc.hex(), dk_hex)


# --------------------------------------------------------------------------- store
class Store:
    def __init__(self, path: str = DB_PATH):
        key = os.getenv(TOKEN_ENCRYPTION_KEY_ENV)
        if not key:
            raise RuntimeError(
                f"{TOKEN_ENCRYPTION_KEY_ENV} must be configured with a persistent Fernet key"
            )
        try:
            self.token_cipher = Fernet(key.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise RuntimeError(
                f"{TOKEN_ENCRYPTION_KEY_ENV} is not a valid Fernet key"
            ) from exc

        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        user_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(users)")}
        if "email" not in user_columns:
            self.db.execute("ALTER TABLE users ADD COLUMN email TEXT")
        self.db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users(lower(email)) "
            "WHERE email IS NOT NULL"
        )
        usage_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(usage_logs)")}
        for column, ddl in _USAGE_LOG_MIGRATIONS:
            if column not in usage_columns:
                self.db.execute(ddl)
        client_columns = {row["name"] for row in self.db.execute("PRAGMA table_info(clients)")}
        for column, ddl in _CLIENT_MIGRATIONS:
            if column not in client_columns:
                self.db.execute(ddl)
        self.db.execute("UPDATE clients SET enabled=0 WHERE owner IS NULL")
        key_check = self.db.execute(
            "SELECT value FROM settings WHERE key='token_encryption_key_check'"
        ).fetchone()
        if key_check:
            try:
                valid_key = self.token_cipher.decrypt(key_check["value"].encode("ascii")) == _TOKEN_KEY_CHECK
            except (InvalidToken, UnicodeEncodeError) as exc:
                self.db.close()
                raise RuntimeError(
                    f"{TOKEN_ENCRYPTION_KEY_ENV} does not match the key used for this database"
                ) from exc
            if not valid_key:
                self.db.close()
                raise RuntimeError(
                    f"{TOKEN_ENCRYPTION_KEY_ENV} does not match the key used for this database"
                )
        else:
            encrypted_check = self.token_cipher.encrypt(_TOKEN_KEY_CHECK).decode("ascii")
            self.db.execute(
                "INSERT INTO settings(key,value) VALUES('token_encryption_key_check',?)",
                (encrypted_check,)
            )
        self.lock = threading.Lock()

    def q(self, sql: str, args=()) -> list:
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def x(self, sql: str, args=()) -> int:
        with self.lock:
            return self.db.execute(sql, args).rowcount

    def one(self, sql: str, args=()) -> Optional[dict]:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    # ---- agents
    def add_agent(self, agent_id: str, label: str = "", owner: str = "",
                  token: Optional[str] = None) -> str:
        if not token:  # None or empty -> generate a fresh token
            tok = new_token("agt")
        else:
            tok = token
        hashed_token = token_hash(tok)
        encrypted_token = encrypt(tok, hashed_token)
        self.x("INSERT INTO agents(agent_id,label,owner,token_hash,encrypted_token,created_at) VALUES(?,?,?,?,?,?)",
            (agent_id, label, owner, hashed_token, encrypted_token, time.time()))
        self.log_event(agent_id, "registered", f"owner={owner}")
        return tok

    def rotate_agent_token(self, agent_id: str) -> Optional[str]:
        tok = new_token("agt")
        hashed_token = token_hash(tok)
        encrypted_token = encrypt(tok, hashed_token)
        if self.x("UPDATE agents SET token_hash=?, encrypted_token=? WHERE agent_id=?", (hashed_token, encrypted_token, agent_id)):
            self.log_event(agent_id, "token_rotated")
            return tok
        return None

    def update_token_by_agent(self, agent_id: str, new_token: str) -> bool:
        hashed_token = token_hash(new_token)
        encrypted_token = encrypt(new_token, hashed_token)
        if self.x("UPDATE agents SET token_hash=?, encrypted_token=? WHERE agent_id=?", (hashed_token, encrypted_token, agent_id)):
            self.log_event(agent_id, "token_updated")
            return True
        return False

    def agent_by_token(self, tok: str) -> Optional[dict]:
        return self.one("SELECT * FROM agents WHERE token_hash=?", (token_hash(tok),))

    def get_agent(self, agent_id: str) -> Optional[dict]:
        return self.one("SELECT * FROM agents WHERE agent_id=?", (agent_id,))

    def list_agents(self) -> list:
        rows = self.q("SELECT * FROM agents ORDER BY agent_id")
        for row in rows:
            encrypted_token = row.get("encrypted_token")
            row["agent_token"] = (
                decrypt(encrypted_token, row["token_hash"]) if encrypted_token else None
            )
        return rows

    def get_latest_agent_version(self) -> Optional[str]:
        row = self.one("SELECT value FROM settings WHERE key='latest_agent_version'")
        return row["value"] if row else None

    def set_latest_agent_version(self, version: str):
        self.x("INSERT INTO settings(key,value) VALUES('latest_agent_version',?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (version,))
        self.log_event(None, "latest_agent_version_set", version)

    def set_agent_enabled(self, agent_id: str, enabled: bool) -> bool:
        ok = self.x("UPDATE agents SET enabled=? WHERE agent_id=?", (int(enabled), agent_id)) > 0
        if ok:
            self.log_event(agent_id, "enabled" if enabled else "disabled")
        return ok

    def touch_agent(self, agent_id: str, **fields):
        if not fields:
            return
        unknown = set(fields) - _AGENT_UPDATABLE_FIELDS
        if unknown:
            raise ValueError(f"Unsupported agent field(s): {', '.join(sorted(unknown))}")
        cols = ",".join(k + "=?" for k in fields)
        self.x(_fill(_TOUCH_AGENT_SQL, "{cols}", cols), (*fields.values(), agent_id))

    def count_job(self, agent_id: str, ok: bool):
        self.x("UPDATE agents SET jobs_ok=jobs_ok+?, jobs_failed=jobs_failed+? WHERE agent_id=?",
               (1 if ok else 0, 0 if ok else 1, agent_id))

    # ---- API clients (scrapers)
    def add_user(self, username: str, email: str, password: str):
        if self.one("SELECT 1 FROM admins WHERE username=?", (username,)):
            raise sqlite3.IntegrityError("username is already an administrator")
        self.x("INSERT INTO users(username,pw_hash,created_at,email) VALUES(?,?,?,?)",
               (username, hash_password(password), time.time(), email.strip().lower()))

    def user_ok(self, username: str, password: str) -> bool:
        row = self.one("SELECT pw_hash,enabled FROM users WHERE username=?", (username,))
        return bool(row and row["enabled"] and verify_password(password, row["pw_hash"]))

    def get_user(self, username: str) -> Optional[dict]:
        return self.one("SELECT username,email,enabled,created_at FROM users WHERE username=?", (username,))

    def user_by_email(self, email: str) -> Optional[dict]:
        return self.one("SELECT username,email,enabled FROM users WHERE lower(email)=?",
                        (email.strip().lower(),))

    def list_users(self) -> list:
        return self.q(
            "SELECT u.username,u.email,u.enabled,u.created_at,COUNT(DISTINCT a.agent_id) AS agents "
            "FROM users u LEFT JOIN agents a ON a.owner=u.username "
            "GROUP BY u.username ORDER BY u.username"
        )

    def set_user_enabled(self, username: str, enabled: bool) -> bool:
        return self.x("UPDATE users SET enabled=? WHERE username=?",
                      (int(enabled), username)) > 0

    def set_user_email(self, username: str, email: str) -> bool:
        return self.x("UPDATE users SET email=? WHERE username=?",
                      (email.strip().lower(), username)) > 0

    def delete_agent(self, agent_id: str) -> bool:
        ok = self.x("DELETE FROM agents WHERE agent_id=?", (agent_id,)) > 0
        if ok:
            self.log_event(agent_id, "deleted")
            self.delete_agent_fetch_sessions(agent_id)
        return ok

    def set_user_password(self, username: str, password: str) -> bool:
        password_hash = hash_password(password)
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                updated = self.db.execute(
                    "UPDATE users SET pw_hash=? WHERE username=?",
                    (password_hash, username)
                ).rowcount
                if updated:
                    self.db.execute(
                        "DELETE FROM dashboard_sessions WHERE username=? AND role='user'",
                        (username,)
                    )
                    self.db.execute("DELETE FROM password_reset_tokens WHERE username=?",
                                    (username,))
                self.db.execute("COMMIT")
                return updated > 0
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def create_password_reset(self, username: str, token: str,
                              expires_at: float, cooldown_sec: int = 60) -> bool:
        now = time.time()
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                recent = self.db.execute(
                    "SELECT 1 FROM password_reset_tokens "
                    "WHERE username=? AND created_at>?",
                    (username, now - cooldown_sec)
                ).fetchone()
                if recent:
                    self.db.execute("COMMIT")
                    return False
                self.db.execute("DELETE FROM password_reset_tokens WHERE username=?",
                                (username,))
                self.db.execute(
                    "INSERT INTO password_reset_tokens(token_hash,username,created_at,expires_at) "
                    "VALUES(?,?,?,?)",
                    (token_hash(token), username, now, expires_at)
                )
                self.db.execute("COMMIT")
                return True
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def delete_password_reset(self, token: str):
        self.x("DELETE FROM password_reset_tokens WHERE token_hash=?", (token_hash(token),))

    def consume_password_reset(self, token: str, password: str) -> bool:
        now = time.time()
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                reset = self.db.execute(
                    "SELECT username FROM password_reset_tokens "
                    "WHERE token_hash=? AND expires_at>?",
                    (token_hash(token), now)
                ).fetchone()
                if not reset:
                    self.db.execute("COMMIT")
                    return False
                username = reset["username"]
                password_hash = hash_password(password)
                updated = self.db.execute(
                    "UPDATE users SET pw_hash=? WHERE username=? AND enabled=1",
                    (password_hash, username)
                ).rowcount
                self.db.execute("DELETE FROM password_reset_tokens WHERE username=?", (username,))
                self.db.execute(
                    "DELETE FROM dashboard_sessions WHERE username=? AND role='user'",
                    (username,)
                )
                self.db.execute("COMMIT")
                return updated > 0
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def add_user_token(self, username: str, client_id: str,
                       location: Optional[str] = None) -> str:
        tok = new_token("usr")
        inserted = self.x(
            "INSERT INTO clients(client_id,token_hash,created_at,owner,location,encrypted_token,"
            "daily_limit,usage_day,usage_count) "
            "VALUES(?,?,?,?,?,?,?,NULL,0) ON CONFLICT(client_id) DO UPDATE SET "
            "token_hash=excluded.token_hash,enabled=1,created_at=excluded.created_at,"
            "last_used=NULL,requests=0,owner=excluded.owner,location=excluded.location,"
            "encrypted_token=excluded.encrypted_token,daily_limit=excluded.daily_limit,"
            "usage_day=NULL,usage_count=0 "
            "WHERE clients.owner IS NULL",
            (client_id, token_hash(tok), time.time(), username, location,
             self.token_cipher.encrypt(tok.encode("utf-8")).decode("ascii"),
             DEFAULT_DAILY_FETCH_LIMIT)
        )
        if not inserted:
            raise sqlite3.IntegrityError("token name already exists")
        return tok

    def rotate_user_token(self, owner: str, client_id: str) -> Optional[tuple[str, list[dict]]]:
        tok = new_token("usr")
        encrypted = self.token_cipher.encrypt(tok.encode("utf-8")).decode("ascii")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                updated = self.db.execute(
                    "UPDATE clients SET token_hash=?,encrypted_token=?,created_at=?,"
                    "last_used=NULL,requests=0 WHERE owner=? AND client_id=?",
                    (token_hash(tok), encrypted, time.time(), owner, client_id)
                ).rowcount
                if not updated:
                    self.db.execute("ROLLBACK")
                    return None
                sessions = [dict(row) for row in self.db.execute(
                    "SELECT session_id,agent_id FROM fetch_sessions WHERE client_id=?",
                    (client_id,)
                ).fetchall()]
                self.db.execute("DELETE FROM fetch_sessions WHERE client_id=?", (client_id,))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        return tok, sessions

    def list_user_tokens(self, owner: Optional[str] = None) -> list:
        if owner is None:
            rows = self.q(
                "SELECT client_id,owner,location,enabled,created_at,last_used,requests,encrypted_token,"
                "daily_limit,usage_day,usage_count "
                "FROM clients WHERE owner IS NOT NULL ORDER BY owner,client_id"
            )
        else:
            rows = self.q(
                "SELECT client_id,owner,location,enabled,created_at,last_used,requests,encrypted_token,"
                "daily_limit,usage_day,usage_count "
                "FROM clients WHERE owner=? ORDER BY client_id", (owner,)
            )
        for row in rows:
            encrypted_token = row.pop("encrypted_token")
            row["token"] = (self.token_cipher.decrypt(encrypted_token.encode("ascii")).decode("utf-8")
                            if encrypted_token else None)
        return rows

    def set_user_token_enabled(self, owner: str, client_id: str, enabled: bool) -> bool:
        return self.x("UPDATE clients SET enabled=? WHERE owner=? AND client_id=?",
                      (int(enabled), owner, client_id)) > 0

    def delete_user_token(self, owner: str, client_id: str) -> Optional[list[dict]]:
        with self.lock:
            row = self.db.execute(
                "SELECT client_id FROM clients WHERE owner=? AND client_id=?",
                (owner, client_id)
            ).fetchone()
            if row is None:
                return None
            sessions = self.db.execute(
                "SELECT session_id,agent_id FROM fetch_sessions WHERE client_id=?",
                (client_id,)
            ).fetchall()
            self.db.execute("DELETE FROM fetch_sessions WHERE client_id=?", (client_id,))
            self.db.execute("DELETE FROM clients WHERE owner=? AND client_id=?",
                            (owner, client_id))
            return [dict(session) for session in sessions]

    # ---- per-token daily /fetch limit
    def consume_fetch_quota(self, client_id: str, day: str) -> dict:
        """Count one /fetch call against the token's limit for `day` (YYYY-MM-DD).

        Atomic check-and-increment, so parallel calls can't overshoot the limit.
        A new day starts the count again at 1: no scheduled reset job is needed.
        """
        with self.lock:
            allowed = self.db.execute(
                "UPDATE clients SET "
                "usage_count = CASE WHEN usage_day = ? THEN usage_count + 1 ELSE 1 END, "
                "usage_day = ? "
                "WHERE client_id = ? AND daily_limit > 0 "
                "AND (usage_day IS NOT ? OR usage_count < daily_limit)",
                (day, day, client_id, day)
            ).rowcount > 0
            row = self.db.execute(
                "SELECT daily_limit, usage_day, usage_count FROM clients WHERE client_id=?",
                (client_id,)
            ).fetchone()
        limit = row["daily_limit"] if row else 0
        used = row["usage_count"] if row and row["usage_day"] == day else 0
        return {"allowed": allowed, "daily_limit": limit, "used": used}

    def refund_fetch_quota(self, client_id: str, day: str):
        """Give back one call when a /fetch never reached an agent."""
        self.x("UPDATE clients SET usage_count = usage_count - 1 "
               "WHERE client_id=? AND usage_day=? AND usage_count > 0", (client_id, day))

    def set_user_token_daily_limit(self, owner: str, client_id: str, daily_limit: int) -> bool:
        return self.x("UPDATE clients SET daily_limit=? WHERE owner=? AND client_id=?",
                      (int(daily_limit), owner, client_id)) > 0

    def location_exists(self, location: str) -> bool:
        return self.one("SELECT 1 FROM agents WHERE label=? LIMIT 1", (location,)) is not None

    def client_by_token(self, tok: str) -> Optional[dict]:
        return self.one("SELECT * FROM clients WHERE token_hash=?", (token_hash(tok),))

    def touch_client(self, client_id: str):
        self.x("UPDATE clients SET last_used=?, requests=requests+1 WHERE client_id=?",
               (time.time(), client_id))

    def log_usage(self, username: str, client_id: str, url: str, method: str,
                  success: bool, status_code: Optional[int], agent_id: Optional[str],
                  duration_sec: float, error: str = "", timestamp: Optional[float] = None,
                  service: str = "unknown", domain: str = ""):
        self.x(
            "INSERT INTO usage_logs(ts,username,client_id,url,method,success,status_code,"
            "agent_id,duration_sec,error,service,domain) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (time.time() if timestamp is None else timestamp, username, client_id,
             url[:2048], method, int(success), status_code,
             agent_id, max(0.0, duration_sec), error[:300], service, domain[:253].lower())
        )

    @staticmethod
    def _usage_where(username: Optional[str], start_ts: Optional[float],
                     end_ts: Optional[float], domain: Optional[str],
                     service: Optional[str], agent_id: Optional[str],
                     result: Optional[str], status_code: Optional[int],
                     client_id: Optional[str]) -> tuple[str, list]:
        clauses, args = [], []
        if username is not None:
            clauses.append("username=?")
            args.append(username)
        if start_ts is not None:
            clauses.append("ts>=?")
            args.append(start_ts)
        if end_ts is not None:
            clauses.append("ts<?")
            args.append(end_ts)
        if domain:
            clauses.append("instr(lower(domain),lower(?))>0")
            args.append(domain.strip().lower())
        if service:
            clauses.append("service=?")
            args.append(service)
        if agent_id:
            clauses.append("instr(lower(agent_id),lower(?))>0")
            args.append(agent_id.strip())
        if result:
            clauses.append("success=?")
            args.append(int(result == "success"))
        if status_code is not None:
            clauses.append("status_code=?")
            args.append(status_code)
        if client_id:
            clauses.append("client_id=?")
            args.append(client_id.strip())
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        return where, args

    def _usage_log_where(self, username, start_ts, end_ts, domain, service, agent_id, result,
                         status_code, client_id, min_id=None, max_id=None) -> tuple[str, list]:
        where, args = self._usage_where(username, start_ts, end_ts, domain, service, agent_id,
                                        result, status_code, client_id)
        extra = []
        if min_id is not None:
            extra.append("id>=?")
            args.append(int(min_id))
        if max_id is not None:
            extra.append("id<=?")
            args.append(int(max_id))
        if extra:
            where = (f"{where} AND " if where else "WHERE ") + " AND ".join(extra)
        return where, args

    def list_usage_logs(self, username: Optional[str], start_ts: Optional[float],
                        end_ts: Optional[float], limit: int = 500,
                        domain: Optional[str] = None, service: Optional[str] = None,
                        agent_id: Optional[str] = None, result: Optional[str] = None,
                        status_code: Optional[int] = None, client_id: Optional[str] = None,
                        sort_order: str = "desc", offset: int = 0,
                        max_id: Optional[int] = None) -> list:
        where, args = self._usage_log_where(
            username, start_ts, end_ts, domain, service, agent_id, result,
            status_code, client_id, max_id=max_id
        )
        args.extend([int(limit), max(0, int(offset))])
        template = _USAGE_LIST_SQL["ASC" if sort_order == "asc" else "DESC"]
        return self.q(_fill(template, "{where}", where), args)

    def count_usage_logs(self, username: Optional[str], start_ts: Optional[float],
                         end_ts: Optional[float], domain: Optional[str] = None,
                         service: Optional[str] = None, agent_id: Optional[str] = None,
                         result: Optional[str] = None, status_code: Optional[int] = None,
                         client_id: Optional[str] = None, min_id: Optional[int] = None,
                         max_id: Optional[int] = None) -> int:
        where, args = self._usage_log_where(
            username, start_ts, end_ts, domain, service, agent_id, result,
            status_code, client_id, min_id=min_id, max_id=max_id
        )
        row = self.one(_fill(_USAGE_COUNT_SQL, "{where}", where), args)
        return int(row["n"]) if row else 0

    def max_usage_log_id(self) -> int:
        row = self.one("SELECT COALESCE(MAX(id), 0) AS m FROM usage_logs")
        return int(row["m"]) if row else 0

    def usage_summary(self, username: Optional[str], start_ts: Optional[float],
                      end_ts: Optional[float], domain: Optional[str] = None,
                      service: Optional[str] = None, agent_id: Optional[str] = None,
                      result: Optional[str] = None, status_code: Optional[int] = None,
                      client_id: Optional[str] = None) -> dict:
        where, args = self._usage_where(
            username, start_ts, end_ts, domain, service, agent_id, result,
            status_code, client_id
        )
        totals = self.one(_fill(_USAGE_TOTALS_SQL, "{where}", where), args)
        days = self.q(_fill(_USAGE_DAYS_SQL, "{where}", where), args)
        return {"totals": totals, "days": days}

    def list_clients(self) -> list:
        return self.q("SELECT client_id,enabled,created_at,last_used,requests FROM clients ORDER BY client_id")

    def recent_events_for_owner(self, owner: str, limit: int = 100,
                                agent_id: Optional[str] = None) -> list:
        if agent_id:
            return self.q(
                "SELECT e.* FROM events e JOIN agents a ON a.agent_id=e.agent_id "
                "WHERE a.owner=? AND e.agent_id=? ORDER BY e.id DESC LIMIT ?",
                (owner, agent_id, limit)
            )
        return self.q(
            "SELECT e.* FROM events e JOIN agents a ON a.agent_id=e.agent_id "
            "WHERE a.owner=? ORDER BY e.id DESC LIMIT ?", (owner, limit)
        )

    # ---- dashboard admins
    def set_admin(self, username: str, password: str):
        if self.one("SELECT 1 FROM users WHERE username=?", (username,)):
            raise sqlite3.IntegrityError("username is already a user account")
        self.x("INSERT INTO admins(username,pw_hash,created_at) VALUES(?,?,?) "
               "ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash",
               (username, hash_password(password), time.time()))

    def admin_exists(self, username: str) -> bool:
        return self.one("SELECT 1 FROM admins WHERE username=?", (username,)) is not None

    def admin_ok(self, username: str, password: str) -> bool:
        row = self.one("SELECT pw_hash FROM admins WHERE username=?", (username,))
        return bool(row) and verify_password(password, row["pw_hash"])

    def create_dashboard_session(self, token: str, username: str, role: str,
                                 expires_at: float):
        self.x("INSERT INTO dashboard_sessions(token_hash,username,role,expires_at) "
               "VALUES(?,?,?,?)", (token_hash(token), username, role, expires_at))

    def dashboard_session(self, token: str) -> Optional[dict]:
        return self.one(
            "SELECT username,role,expires_at FROM dashboard_sessions "
            "WHERE token_hash=? AND expires_at>?", (token_hash(token), time.time())
        )

    def delete_dashboard_session(self, token: str):
        self.x("DELETE FROM dashboard_sessions WHERE token_hash=?", (token_hash(token),))

    # ---- office / VPN egress networks (agents exiting through these are skipped)
    @staticmethod
    def normalize_network(value: str) -> str:
        """'203.0.113.10' -> '203.0.113.10/32'; '203.0.113.7/28' -> '203.0.113.0/28'. Raises ValueError."""
        return str(ipaddress.ip_network(value.strip(), strict=False))

    def add_office_network(self, value: str, label: str = "") -> str:
        cidr = self.normalize_network(value)
        self.x("INSERT INTO office_networks(cidr,label,created_at) VALUES(?,?,?)", (cidr, label, time.time()))
        self.log_event(None, "office_network_added", f"{cidr} {label}".strip())
        return cidr

    def remove_office_network(self, value: str) -> bool:
        cidr = self.normalize_network(value)
        ok = self.x("DELETE FROM office_networks WHERE cidr=?", (cidr,)) > 0
        if ok:
            self.log_event(None, "office_network_removed", cidr)
        return ok

    def list_office_networks(self) -> list:
        return self.q("SELECT cidr,label,created_at FROM office_networks ORDER BY cidr")

    # ---- requests sessions
    def create_fetch_session(self, session_id: str, client_id: str, agent_id: str,
                             timestamp: Optional[float] = None):
        now = time.time() if timestamp is None else timestamp
        self.x("INSERT INTO fetch_sessions(session_id,client_id,agent_id,created_at,last_used) "
               "VALUES(?,?,?,?,?)", (session_id, client_id, agent_id, now, now))

    def get_fetch_session(self, session_id: str) -> Optional[dict]:
        return self.one("SELECT session_id,client_id,agent_id,created_at,last_used "
                        "FROM fetch_sessions WHERE session_id=?", (session_id,))

    def touch_fetch_session(self, session_id: str, timestamp: Optional[float] = None) -> bool:
        now = time.time() if timestamp is None else timestamp
        return self.x("UPDATE fetch_sessions SET last_used=? WHERE session_id=?",
                      (now, session_id)) > 0

    def delete_fetch_session(self, session_id: str) -> Optional[dict]:
        with self.lock:
            row = self.db.execute(
                "SELECT session_id,client_id,agent_id,created_at,last_used "
                "FROM fetch_sessions WHERE session_id=?", (session_id,)
            ).fetchone()
            if row is None:
                return None
            self.db.execute("DELETE FROM fetch_sessions WHERE session_id=?", (session_id,))
            return dict(row)

    def delete_expired_fetch_sessions(self, inactive_before: float) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                "SELECT session_id,client_id,agent_id,created_at,last_used "
                "FROM fetch_sessions WHERE last_used<=?", (inactive_before,)
            ).fetchall()
            if rows:
                self.db.executemany("DELETE FROM fetch_sessions WHERE session_id=?",
                                    [(row["session_id"],) for row in rows])
            return [dict(row) for row in rows]

    def delete_agent_fetch_sessions(self, agent_id: str) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                "SELECT session_id,client_id,agent_id,created_at,last_used "
                "FROM fetch_sessions WHERE agent_id=?", (agent_id,)
            ).fetchall()
            if rows:
                self.db.execute("DELETE FROM fetch_sessions WHERE agent_id=?", (agent_id,))
            return [dict(row) for row in rows]

    # ---- events
    def log_event(self, agent_id: Optional[str], event: str, detail: str = ""):
        self.x("INSERT INTO events(ts,agent_id,event,detail) VALUES(?,?,?,?)",
               (time.time(), agent_id, event, detail[:500]))

    def recent_events(self, limit: int = 100, agent_id: Optional[str] = None) -> list:
        if agent_id:
            return self.q("SELECT * FROM events WHERE agent_id=? ORDER BY id DESC LIMIT ?", (agent_id, limit))
        return self.q("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    def prune_events(self, keep_days: int = 30):
        self.x("DELETE FROM events WHERE ts < ?", (time.time() - keep_days * 86400,))
