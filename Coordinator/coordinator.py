"""
Coordinator for the employee-machine fetch network (v2).

Auth model
  * Scrapers  -> POST /fetch            Authorization: Bearer <client token>
  * Admins    -> /dashboard, admin APIs username/password login with revocable session cookie
  * Users     -> /dashboard, username/password login; fleet and machine metrics are shared,
                 while bearer-token management is limited to their own account
  * Agents    -> WS /agent              per-machine agent token in the hello message
  Agent --owner associates it with a dashboard user and --label is its location.
  All users can dispatch to any enabled connected agent unless a token has a
  location scope. Create accounts and bearer tokens from the admin dashboard.
  Legacy unowned client tokens are disabled on startup.

For requests cookie sessions, POST `{"session": true}` to receive a `session_id`,
then send that ID on later requests to route them to the same agent. Session
ownership and activity timestamps are stored in SQLite; inactive sessions expire
after 30 minutes.

Office / VPN egress IPs live in the office_networks table (python admin.py add-office-ip ...).
Agents whose egress IP falls inside one of them are skipped. The list is reloaded every 15 s.
  Repeated auth failures from one IP are throttled (HTTP 429).

User accounts require an email address; admins can assign one to older accounts in Users.
Configure SMTP_HOST, SMTP_FROM, and an HTTPS PUBLIC_BASE_URL for password reset emails.
SMTP_PORT defaults to 587 with STARTTLS;
SMTP_USE_SSL=true selects implicit TLS (typically port 465). SMTP_USERNAME and
SMTP_PASSWORD are optional but must be configured together.
Fetch usage logs include URL and outcome metadata, but never response bodies; credentials
and token-like query values are redacted before URLs are stored.

Run (single worker; live agent sockets are in memory):
    # Generate once; persist this secret in the coordinator service environment.
    # python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Keep it backed up and unchanged; configure it for both the service and admin CLI.
    # PowerShell current session: $env:COORD_TOKEN_ENCRYPTION_KEY = "<generated value>"
    python admin.py add-admin ops
    python admin.py add-agent LAPTOP-0142 --owner Emp_A --label Chennai
    # Then create the Emp_A account and a location-scoped token in /dashboard.
    uvicorn coordinator:app --host 127.0.0.1 --port 8000 --workers 1 \
        --proxy-headers --forwarded-allow-ips 127.0.0.1
Put Caddy/nginx in front for TLS (https:// and wss://). Never expose plain http -
Passwords, session cookies, and bearer tokens must only travel over TLS.
"""
import asyncio
import base64
import csv
import io
import ipaddress
import json
import logging
import os
import secrets
import smtplib
import sqlite3
import ssl
import time
import uuid
import zlib
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Literal, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, HttpUrl
from starlette.websockets import WebSocketState
from fastapi.staticfiles import StaticFiles

from zoneinfo import ZoneInfo

from store import DEFAULT_DAILY_FETCH_LIMIT, Store


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("coordinator")

DOMAIN_COOLDOWN_SEC = float(os.getenv("DOMAIN_COOLDOWN_SEC", "5"))
AGENT_WAIT_SEC = float(os.getenv("AGENT_WAIT_SEC", "15"))
HEARTBEAT_STALE_SEC = 60
FETCH_SESSION_TTL_SEC = 30 * 60
DASHBOARD_SESSION_TTL_SEC = 12 * 60 * 60
MAX_AUTH_FAILS, AUTH_FAIL_WINDOW = 10, 300          # per source IP
PASSWORD_RESET_TTL_SEC = 60 * 60
PASSWORD_RESET_ATTEMPTS, PASSWORD_RESET_WINDOW_SEC = 5, 15 * 60
# Per-token daily /fetch limits reset at midnight in this time zone.
FETCH_LIMIT_TZ_NAME = os.getenv("FETCH_LIMIT_TIMEZONE", "Asia/Kolkata")
FETCH_LIMIT_TZ = ZoneInfo(FETCH_LIMIT_TZ_NAME)
DASHBOARD_HTML = Path(__file__).with_name("dashboard.html")
DASHBOARD_LOGIN_HTML = Path(__file__).with_name("dashboard_login.html")

store = Store()
_password_reset_attempts: dict[str, deque] = defaultdict(deque)


def _throttle_password_reset(ip: str):
    attempts, now = _password_reset_attempts[ip], time.time()
    while attempts and now - attempts[0] > PASSWORD_RESET_WINDOW_SEC:
        attempts.popleft()
    if len(attempts) >= PASSWORD_RESET_ATTEMPTS:
        raise HTTPException(429, "too many password reset requests; try later")
    attempts.append(now)


def _password_reset_mail_settings() -> dict:
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM", "").strip()
    public_base_url = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
    try:
        parsed_base_url = urlsplit(public_base_url)
        valid_base_url = (
            parsed_base_url.scheme == "https" and parsed_base_url.hostname
            and not parsed_base_url.username and not parsed_base_url.password
            and not parsed_base_url.query and not parsed_base_url.fragment
        )
    except ValueError:
        valid_base_url = False
    if not host or not sender or not valid_base_url:
        raise RuntimeError("SMTP_HOST, SMTP_FROM, and an HTTPS PUBLIC_BASE_URL are required")
    try:
        port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError as exc:
        raise RuntimeError("SMTP_PORT must be a valid port number") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("SMTP_PORT must be between 1 and 65535")
    username = os.getenv("SMTP_USERNAME", "")
    password = os.getenv("SMTP_PASSWORD", "")
    if bool(username) != bool(password):
        raise RuntimeError("SMTP_USERNAME and SMTP_PASSWORD must both be configured")
    use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
    use_starttls = os.getenv("SMTP_STARTTLS", "true").lower() == "true"
    if not use_ssl and not use_starttls:
        raise RuntimeError("SMTP must use SSL or STARTTLS")
    return {
        "host": host, "port": port, "sender": sender,
        "base_url": public_base_url, "username": username,
        "password": password, "use_ssl": use_ssl, "use_starttls": use_starttls,
    }


def _send_password_reset_email(address: str, token: str, settings: dict):
    reset_url = f"{settings['base_url']}/login#{urlencode({'reset': token})}"
    message = EmailMessage()
    message["Subject"] = "Reset your crawler dashboard password"
    message["From"] = settings["sender"]
    message["To"] = address
    message.set_content(
        "A password reset was requested for your crawler dashboard account.\n\n"
        f"Reset your password using this one-time link (valid for one hour):\n{reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )
    context = ssl.create_default_context()
    if settings["use_ssl"]:
        with smtplib.SMTP_SSL(settings["host"], settings["port"], timeout=10,
                              context=context) as smtp:
            if settings["username"]:
                smtp.login(settings["username"], settings["password"])
            smtp.send_message(message)
    else:
        with smtplib.SMTP(settings["host"], settings["port"], timeout=10) as smtp:
            smtp.ehlo()
            if settings["use_starttls"]:
                smtp.starttls(context=context)
                smtp.ehlo()
            if settings["username"]:
                smtp.login(settings["username"], settings["password"])
            smtp.send_message(message)


class OfficeNetworks:
    """Office/VPN egress networks from the office_networks table, cached in memory.

    Checked on every dispatch, so it's kept in memory and reloaded by the sweeper
    every 15 s - changes made with admin.py apply without restarting the coordinator.
    """

    def __init__(self):
        self.networks: list = []

    def reload(self):
        nets = []
        for row in store.list_office_networks():
            try:
                nets.append(ipaddress.ip_network(row["cidr"], strict=False))
            except ValueError:
                log.warning("ignoring invalid office network in DB: %r", row["cidr"])
        if [str(n) for n in nets] != [str(n) for n in self.networks]:
            log.info("office networks loaded: %s", ", ".join(map(str, nets)) or "none")
        self.networks = nets

    def contains(self, ip: Optional[str]) -> bool:
        if not ip or not self.networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)


office_networks = OfficeNetworks()


# =========================================================================== auth
_auth_failures: dict[str, deque] = defaultdict(deque)


def _throttle(ip: str):
    q, now = _auth_failures[ip], time.time()
    while q and now - q[0] > AUTH_FAIL_WINDOW:
        q.popleft()
    if len(q) >= MAX_AUTH_FAILS:
        raise HTTPException(429, "too many failed authentication attempts; try later")


def _record_fail(ip: str, kind: str):
    _auth_failures[ip].append(time.time())
    log.warning("auth failure (%s) from %s", kind, ip)


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


_bearer = HTTPBearer(auto_error=False)


def require_client(request: Request,
                   cred: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> dict:
    ip = _ip(request)
    _throttle(ip)
    row = store.client_by_token(cred.credentials) if cred else None
    account = store.get_user(row["owner"]) if row and row["owner"] else None
    if (not row or not row["enabled"] or not row["owner"]
            or (row["owner"] and (not account or not account["enabled"]))):
        _record_fail(ip, "client")
        raise HTTPException(401, "invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    store.touch_client(row["client_id"])
    return row


def _dashboard_user(request: Request) -> Optional[dict[str, str]]:
    token = request.cookies.get("dashboard_session")
    if not token:
        return None
    session = store.dashboard_session(token)
    if not session:
        return None
    username, role = session["username"], session["role"]
    if role == "admin":
        if not store.admin_exists(username):
            store.delete_dashboard_session(token)
            return None
    elif role == "user":
        account = store.get_user(username)
        if not account or not account["enabled"]:
            store.delete_dashboard_session(token)
            return None
    else:
        store.delete_dashboard_session(token)
        return None
    return {"username": username, "role": role}


def require_dashboard_user(request: Request) -> dict[str, str]:
    user = _dashboard_user(request)
    if not user:
        raise HTTPException(401, "dashboard login required")
    return user


def require_admin(request: Request, user: dict[str, str] = Depends(require_dashboard_user)) -> str:
    if user["role"] != "admin":
        raise HTTPException(403, "administrator account required")
    return user["username"]


def require_admin_write(request: Request, user: str = Depends(require_admin)) -> str:
    # CSRF guard: browsers can't add custom headers cross-site without a CORS preflight
    if request.headers.get("x-requested-with") != "dashboard":
        raise HTTPException(403, "missing X-Requested-With header")
    return user


def require_dashboard_write(
        request: Request,
        user: dict[str, str] = Depends(require_dashboard_user)) -> dict[str, str]:
    if request.headers.get("x-requested-with") != "dashboard":
        raise HTTPException(403, "missing X-Requested-With header")
    return user


# =========================================================================== live registry
@dataclass
class LiveAgent:
    agent_id: str
    ws: WebSocket
    can_render: bool
    max_concurrency: int
    remote_ip: str
    owner: str = ""
    location: str = ""
    egress_ip: Optional[str] = None
    paused: bool = False
    pause_reason: Optional[str] = None
    mb_today: float = 0.0
    inflight: int = 0
    failures: int = 0
    stale: bool = False
    connected_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_db_touch: float = 0.0
    last_hit: dict = field(default_factory=dict)
    pending: dict = field(default_factory=dict)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def available(self) -> bool:
        return (not self.paused and not office_networks.contains(self.egress_ip)
                and self.inflight < self.max_concurrency
                and time.time() - self.last_seen < HEARTBEAT_STALE_SEC)


class Registry:
    def __init__(self):
        self.agents: dict[str, LiveAgent] = {}
        self.lock = asyncio.Lock()

    async def add(self, agent: LiveAgent):
        async with self.lock:
            old = self.agents.get(agent.agent_id)
            self.agents[agent.agent_id] = agent
        if old:  # same machine reconnected (e.g. after sleep) before the old socket timed out
            _fail_pending(old, "agent reconnected")
            try:
                await old.ws.close(code=4409)
            except Exception:
                pass

    async def remove(self, agent: LiveAgent) -> bool:
        async with self.lock:
            if self.agents.get(agent.agent_id) is agent:
                del self.agents[agent.agent_id]
                return True
            return False

    async def acquire(self, domain: str, need_render: bool, exclude: set,
                      agent_id: Optional[str] = None,
                      location: Optional[str] = None) -> Optional[LiveAgent]:
        deadline = time.time() + AGENT_WAIT_SEC
        while time.time() < deadline:
            async with self.lock:
                now = time.time()
                cands = [a for a in self.agents.values()
                         if (agent_id is None or a.agent_id == agent_id)
                         and (location is None or a.location == location)
                         and a.agent_id not in exclude and a.available()
                         and (a.can_render or not need_render)
                         and now - a.last_hit.get(domain, 0) >= DOMAIN_COOLDOWN_SEC]
                if cands:
                    a = min(cands, key=lambda a: (a.failures, a.inflight, a.last_hit.get(domain, 0)))
                    a.inflight += 1
                    a.last_hit[domain] = now
                    return a
            await asyncio.sleep(0.25)
        return None

    async def release(self, agent: LiveAgent):
        async with self.lock:
            agent.inflight = max(0, agent.inflight - 1)


registry = Registry()


def _fail_pending(agent: LiveAgent, reason: str):
    for fut in list(agent.pending.values()):
        if not fut.done():
            fut.set_exception(ConnectionError(reason))
    agent.pending.clear()


async def _notify_session_deletions(agent_id: str, session_ids: list[str], reason: str):
    agent = registry.agents.get(agent_id)
    if not agent or not session_ids:
        return
    try:
        async with agent.send_lock:
            await agent.ws.send_text(json.dumps({
                "type": "delete_sessions",
                "session_ids": session_ids,
            }))
    except (WebSocketDisconnect, RuntimeError, ConnectionError) as exc:
        log.warning("could not delete requests sessions on agent %s (%s): %s",
                    agent_id, reason, exc)


async def _delete_agent_sessions(agent_id: str, reason: str):
    rows = store.delete_agent_fetch_sessions(agent_id)
    if rows:
        session_ids = [row["session_id"] for row in rows]
        log.info("deleted %d requests session(s) for agent %s: %s",
                 len(session_ids), agent_id, reason)
        await _notify_session_deletions(agent_id, session_ids, reason)


async def _delete_expired_sessions():
    rows = store.delete_expired_fetch_sessions(time.time() - FETCH_SESSION_TTL_SEC)
    by_agent: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        by_agent[row["agent_id"]].append(row["session_id"])
    for agent_id, session_ids in by_agent.items():
        log.info("deleted %d inactive requests session(s) for agent %s",
                 len(session_ids), agent_id)
        await _notify_session_deletions(agent_id, session_ids, "inactive for over 30 minutes")


def agent_status(row: dict, live: Optional[LiveAgent], office_networks: list) -> tuple[str, str]:
    """Return (state, status). state is the simple active/inactive view."""
    if not row["enabled"]:
        status = "disabled"
    elif live is None or row["egress_ip"] is None:
        status = "never_connected" if row["last_connected"] is None else "offline"
    elif time.time() - live.last_seen > HEARTBEAT_STALE_SEC:
        status = "stale"                     # socket open but silent - usually asleep
    elif any(row["egress_ip"] in network for network in office_networks):
        status = "blacklisted_network"                 # agent is on an office/VPN network
    elif live.paused:
        status = "paused"
    else:
        status = "active"
    return ("active" if status == "active" else "inactive"), status


# =========================================================================== background sweeper
async def sweeper():
    """Kicks disabled agents, logs stale/recovered transitions, prunes old events."""
    last_prune = 0.0
    while True:
        await asyncio.sleep(15)
        try:
            office_networks.reload()
            await _delete_expired_sessions()
            for a in list(registry.agents.values()):
                row = store.get_agent(a.agent_id)
                if not row or not row["enabled"]:
                    store.log_event(a.agent_id, "kicked", "disabled by admin")
                    await _delete_agent_sessions(a.agent_id, "agent disabled")
                    try:
                        await a.ws.close(code=4403)
                    except Exception:
                        pass
                    continue
                if office_networks.contains(a.egress_ip):
                    await _delete_agent_sessions(a.agent_id, "agent on a blacklisted network")
                stale = time.time() - a.last_seen > HEARTBEAT_STALE_SEC
                if stale != a.stale:
                    a.stale = stale
                    store.log_event(a.agent_id, "stale" if stale else "recovered",
                                    "no heartbeat for >60s" if stale else "")
                    if stale:
                        await _delete_agent_sessions(a.agent_id, "agent offline or stale")
            if time.time() - last_prune > 86400:
                store.prune_events(30)
                last_prune = time.time()
        except Exception:
            log.exception("sweeper error")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    legacy = [v for v in os.getenv("OFFICE_EGRESS_IPS", "").split(",") if v.strip()]
    if legacy and not store.list_office_networks():
        # one-time migration from the old environment variable
        for v in legacy:
            try:
                store.add_office_network(v, "imported from OFFICE_EGRESS_IPS")
            except Exception as e:
                log.warning("could not import office IP %r: %s", v, e)
    office_networks.reload()
    task = asyncio.create_task(sweeper())
    yield
    task.cancel()


app = FastAPI(title="Residential fetch coordinator", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)   # don't publish the API schema

app.mount("/static", StaticFiles(directory="static"), name="static")


# =========================================================================== agent socket
@app.websocket("/agent")
async def agent_socket(ws: WebSocket):
    ip = ws.client.host if ws.client else "unknown"
    await ws.accept()
    try:
        _throttle(ip)
        hello = json.loads(await asyncio.wait_for(ws.receive_text(), timeout=10))
    except WebSocketDisconnect:
        log.info("agent connection from %s closed before hello", ip)
        return
    except Exception as exc:
        log.warning("invalid agent hello from %s: %s", ip, exc)
        if ws.client_state != WebSocketState.DISCONNECTED:
            await ws.close(code=4429 if len(_auth_failures[ip]) >= MAX_AUTH_FAILS else 4400)
        return
    row = store.agent_by_token(str(hello.get("token", ""))) if hello.get("type") == "hello" else None
    if not row:
        _record_fail(ip, "agent")
        await ws.close(code=4401)
        return
    if not row["enabled"]:
        await ws.close(code=4403)
        return

    agent = LiveAgent(agent_id=row["agent_id"], ws=ws, remote_ip=ip,
                      owner=row["owner"] or "", location=row["label"] or "",
                      can_render=bool(hello.get("can_render")),
                      max_concurrency=max(1, min(int(hello.get("max_concurrency", 1)), 5)))
    await registry.add(agent)
    await _delete_agent_sessions(agent.agent_id, "agent reconnected")
    now = time.time()
    store.touch_agent(agent.agent_id, last_connected=now, last_seen=now,
                      platform=str(hello.get("platform", ""))[:120],
                      agent_version=str(hello.get("version", ""))[:64])
    store.log_event(agent.agent_id, "connected", f"from {ip}")
    log.info("agent %s connected from %s", agent.agent_id, ip)

    try:
        while True:
            msg = json.loads(await ws.receive_text())
            agent.last_seen = time.time()
            mtype = msg.get("type")
            if mtype == "heartbeat":
                paused, reason = bool(msg.get("paused")), msg.get("pause_reason")
                if paused != agent.paused:
                    store.log_event(agent.agent_id, "paused" if paused else "resumed", reason or "")
                egress = msg.get("egress_ip")
                if egress and egress != agent.egress_ip:
                    store.log_event(agent.agent_id, "egress_ip", egress)
                    agent.egress_ip = egress
                agent.paused, agent.pause_reason = paused, reason
                agent.mb_today = float(msg.get("mb_today") or 0)
                if office_networks.contains(agent.egress_ip):
                    await _delete_agent_sessions(
                        agent.agent_id, "agent on a blacklisted network")
                if agent.last_seen - agent.last_db_touch > 60:      # limit DB writes
                    store.touch_agent(agent.agent_id, last_seen=agent.last_seen, egress_ip=agent.egress_ip)
                    agent.last_db_touch = agent.last_seen
            elif mtype == "result":
                fut = agent.pending.pop(msg.get("job_id"), None)
                if fut and not fut.done():
                    fut.set_result(msg)
    except (WebSocketDisconnect, RuntimeError, json.JSONDecodeError):
        pass
    finally:
        if await registry.remove(agent):
            store.touch_agent(agent.agent_id, last_disconnected=time.time(), last_seen=agent.last_seen)
            store.log_event(agent.agent_id, "disconnected")
            log.info("agent %s disconnected", agent.agent_id)
        await _delete_agent_sessions(agent.agent_id, "agent disconnected")
        _fail_pending(agent, "agent disconnected")


# =========================================================================== scraper API
class FetchRequest(BaseModel):
    url: HttpUrl
    render: bool = False
    service: str = Field("requests", pattern="^(requests|playwright|selenium|nodriver)$") 
    session: bool = False
    session_id: Optional[str] = Field(None, min_length=1, max_length=128)
    http_method: str = Field("GET", pattern="^(GET|POST)$")
    json: Optional[Any] = None
    data: Optional[Any] = None
    timeout: int = Field(30, ge=5, le=120)
    wait_until: str = Field("load", pattern="^(load|domcontentloaded|networkidle|commit)$")
    wait_seconds: int = Field(0, ge=0, le=300)
    wait_for_selector: Optional[str] = None
    headers: dict[str, str] = {}
    max_retries: int = Field(2, ge=0, le=5)


class OfficeNetworkCreate(BaseModel):
    network: str = Field(min_length=1, max_length=64)
    label: str = Field("", max_length=120)


class AgentCreate(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    label: str = Field("", max_length=80)
    owner: str = Field("", max_length=64)
    token: Optional[str] = Field(None, min_length=16, max_length=256)


def _unavailable_reasons(need_render: bool, location: Optional[str] = None) -> dict:
    out = {}
    for a in registry.agents.values():
        if location is not None and a.location != location:
            continue
        if a.pause_reason:
            why = a.pause_reason
        elif office_networks.contains(a.egress_ip):
            why = "on office network"
        elif time.time() - a.last_seen > HEARTBEAT_STALE_SEC:
            why = "not responding"
        elif a.inflight >= a.max_concurrency:
            why = "busy"
        elif need_render and not a.can_render:
            why = "no render support"
        else:
            why = "domain cooldown"
        out[a.agent_id] = why
    return out


def _usage_url(url: str) -> str:
    parts = urlsplit(url)
    query = []
    sensitive_parts = ("token", "key", "secret", "pass", "auth", "credential",
                       "signature", "session")
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if any(part in key.casefold() for part in sensitive_parts):
            value = "[redacted]"
        query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1],
                       parts.path, urlencode(query), ""))


def _quota_day() -> tuple[str, datetime]:
    """Today's date in the limit time zone, and when the next day starts."""
    now = datetime.now(FETCH_LIMIT_TZ)
    reset = datetime.combine(now.date() + timedelta(days=1), datetime_time.min, tzinfo=FETCH_LIMIT_TZ)
    return now.date().isoformat(), reset


def _quota_view(row: dict, day: str, reset: datetime) -> dict:
    limit = int(row.get("daily_limit") or 0)
    used = int(row.get("usage_count") or 0) if row.get("usage_day") == day else 0
    return {"daily_limit": limit, "used_today": used, "remaining_today": max(limit - used, 0),
            "resets_at": reset.isoformat(), "limit_timezone": FETCH_LIMIT_TZ_NAME}


def _tokens_with_quota(rows: list[dict]) -> list[dict]:
    day, reset = _quota_day()
    out = []
    for row in rows:
        row = dict(row)
        row.update(_quota_view(row, day, reset))
        row.pop("usage_day", None)
        row.pop("usage_count", None)
        out.append(row)
    return out


def _quota_headers(limit: int, used: int, reset: datetime) -> dict[str, str]:
    return {"X-RateLimit-Limit": str(limit), "X-RateLimit-Remaining": str(max(limit - used, 0)),
            "X-RateLimit-Reset": str(int(reset.timestamp()))}


@app.post("/fetch")
async def fetch(req: FetchRequest, response: Response, client: dict = Depends(require_client)):
    started_at = time.time()
    domain = urlsplit(str(req.url)).hostname or ""

    # Daily per-token limit. Counted up front so parallel calls can't exceed it.
    day, reset = _quota_day()
    quota = store.consume_fetch_quota(client["client_id"], day)
    if not quota["allowed"]:
        detail = {"error": "token limit exceeded",
                  "message": f"This token has used its {quota['daily_limit']} fetch calls for today.",
                  "daily_limit": quota["daily_limit"], "used_today": quota["used"],
                  "remaining_today": 0, "resets_at": reset.isoformat()}
        store.log_usage(client["owner"], client["client_id"], _usage_url(str(req.url)), req.http_method,
                        False, 429, None, 0.0, "token limit exceeded",
                        timestamp=started_at, service=req.service, domain=domain)
        raise HTTPException(429, detail, headers={
            **_quota_headers(quota["daily_limit"], quota["used"], reset),
            "Retry-After": str(max(1, int(reset.timestamp() - time.time())))})
    response.headers.update(_quota_headers(quota["daily_limit"], quota["used"], reset))
    quota_info = {"daily_limit": quota["daily_limit"], "used_today": quota["used"],
                  "remaining_today": max(quota["daily_limit"] - quota["used"], 0),
                  "resets_at": reset.isoformat()}

    try:
        result = await _dispatch_fetch(req, client)
    except HTTPException as exc:
        # Only calls that reached an agent count. 502 = agents tried and failed or were
        # blocked, so it counts; everything else (no agent, bad session, validation) is refunded.
        if exc.status_code != 502:
            store.refund_fetch_quota(client["client_id"], day)
        detail = exc.detail
        if isinstance(detail, dict):
            error = str(detail.get("error") or detail.get("connected_agents") or detail)
            attempted_agents = detail.get("agents_tried") or []
            agent_id = ", ".join(str(agent) for agent in attempted_agents) or None
        else:
            error = str(detail)
            agent_id = None
        store.log_usage(client["owner"], client["client_id"], _usage_url(str(req.url)), req.http_method,
                        False, exc.status_code, agent_id, time.time() - started_at, error,
                        timestamp=started_at, service=req.service, domain=domain)
        raise
    except Exception as exc:
        store.refund_fetch_quota(client["client_id"], day)
        store.log_usage(client["owner"], client["client_id"], _usage_url(str(req.url)), req.http_method,
                        False, 500, None, time.time() - started_at,
                        f"{type(exc).__name__}: {exc}", timestamp=started_at,
                        service=req.service, domain=domain)
        raise
    store.log_usage(client["owner"], client["client_id"], _usage_url(str(req.url)), req.http_method,
                    True, result.get("status_code"), result.get("agent_id"),
                    time.time() - started_at, result.get("error") or "",
                    timestamp=started_at, service=req.service, domain=domain)
    if isinstance(result, dict):
        result["quota"] = quota_info
    return result


async def _dispatch_fetch(req: FetchRequest, client: dict):
    client_id = client["client_id"]
    location = client["location"]
    url = str(req.url)
    domain = urlparse(url).hostname or ""
    if (req.session or req.session_id) and req.service != "requests":
        raise HTTPException(422, "sessions are only supported by the requests service")

    session_id = req.session_id
    session_action = "reuse" if session_id else ("create" if req.session else None)
    pinned_agent_id = None
    if session_action == "reuse":
        session_row = store.get_fetch_session(session_id)
        if not session_row or session_row["client_id"] != client_id:
            raise HTTPException(404, "unknown or expired session_id")
        if time.time() - session_row["last_used"] >= FETCH_SESSION_TTL_SEC:
            expired = store.delete_fetch_session(session_id)
            if expired:
                await _notify_session_deletions(
                    expired["agent_id"], [session_id], "inactive for over 30 minutes")
            raise HTTPException(404, "unknown or expired session_id")
        pinned_agent_id = session_row["agent_id"]
        session_agent_row = store.get_agent(pinned_agent_id)
        if location is not None and (
                not session_agent_row or session_agent_row["label"] != location):
            raise HTTPException(404, "unknown or expired session_id")
        session_agent = registry.agents.get(pinned_agent_id)
        if (session_agent is None
                or time.time() - session_agent.last_seen > HEARTBEAT_STALE_SEC
                or office_networks.contains(session_agent.egress_ip)):
            await _delete_agent_sessions(
                pinned_agent_id, "agent offline or on a blacklisted network")
            raise HTTPException(404, "unknown or expired session_id")
        store.touch_fetch_session(session_id)

    tried: list[str] = []
    last_error = None
    for attempt in range(req.max_retries + 1):
        agent = await registry.acquire(
            domain, req.render, exclude=set() if pinned_agent_id else set(tried),
            agent_id=pinned_agent_id, location=location,
        )
        if agent is None:
            if attempt == 0:
                detail = {"error": "no agent available",
                          "connected_agents": _unavailable_reasons(
                              req.render, location=location) or "none connected"}
                if session_id:
                    detail["session_id"] = session_id
                raise HTTPException(503, detail)
            break
        tried.append(agent.agent_id)
        if session_action == "create" and session_id is None:
            session_id = uuid.uuid4().hex
            pinned_agent_id = agent.agent_id
            store.create_fetch_session(session_id, client_id, agent.agent_id)

        job_id = uuid.uuid4().hex
        fut = asyncio.get_running_loop().create_future()
        agent.pending[job_id] = fut
        job_body = req.model_dump(mode="json", exclude={"max_retries", "session"})
        if session_id:
            job_body["session_id"] = session_id
            job_body["session_action"] = session_action
        try:
            async with agent.send_lock:
                await agent.ws.send_text(json.dumps({"type": "job", "job_id": job_id, **job_body}))
            res = await asyncio.wait_for(fut, timeout=req.timeout + 15)
        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            agent.failures += 1
            store.count_job(agent.agent_id, ok=False)
            continue
        finally:
            agent.pending.pop(job_id, None)
            await registry.release(agent)

        if res.get("ok") and not res.get("blocked"):
            agent.failures = max(0, agent.failures - 1)
            store.count_job(agent.agent_id, ok=True)
            # if "body_b64z" in res:
            #     html = zlib.decompress(base64.b64decode(res["body_b64z"])).decode("utf-8", "replace")
            # else:
            #     html = res.get("object")
            return {"url": url, "final_url": res.get("final_url"), "status": res.get("status"),
                    "render": req.render, "content": res.get("content"), "agent_id": agent.agent_id,
                    "session_id": session_id,
                    "egress_ip": agent.egress_ip, "elapsed_sec": res.get("elapsed"),
                    "attempts": attempt + 1, "service": res.get("service"), 
                    "status_code": res.get("status_code"), "tat_ms": res.get("tat_ms"),
                    "blocked": res.get("blocked"), "block_message": res.get("block_message"),
                    "error": res.get("error"), "content_length": res.get("content_length"),
                    "content_type": res.get("content_type"),
                    "content_encoding": res.get("content_encoding"),
                    "filename": res.get("filename"), "truncated": res.get("truncated"),
                    "request": res.get("request")}
        agent.failures += 1
        store.count_job(agent.agent_id, ok=False)
        last_error = res.get("error") or f"blocked (HTTP {res.get('status')})"
        log.warning("client=%s job=%s agent=%s failed: %s", client_id, job_id, agent.agent_id, last_error)

    detail = {"error": last_error, "agents_tried": tried}
    if session_id:
        detail["session_id"] = session_id
    raise HTTPException(502, detail=detail)


# =========================================================================== admin API + dashboard
def _agent_rows(owner: Optional[str] = None) -> list[dict]:
    out = []
    latest_agent_version = store.get_latest_agent_version()
    office_networks = []
    for row in store.list_office_networks():
        try:
            office_networks.append(row["cidr"])
        except ValueError:
            pass
    for row in store.list_agents():
        if owner is not None and row["owner"] != owner:
            continue
        live = registry.agents.get(row["agent_id"])
        state, status = agent_status(row, live, office_networks)
        out.append({
            "agent_id": row["agent_id"], "label": row["label"], "owner": row["owner"],
            "location": row["label"] or "",
            "enabled": bool(row["enabled"]), "state": state, "status": status,
            "pause_reason": live.pause_reason if live else None,
            "egress_ip": (live.egress_ip if live else None) or row["egress_ip"],
            "remote_ip": live.remote_ip if live else None,
            "can_render": live.can_render if live else None,
            "inflight": live.inflight if live else 0,
            "max_concurrency": live.max_concurrency if live else None,
            "mb_today": live.mb_today if live else None,
            "last_seen": live.last_seen if live else row["last_seen"],
            "last_connected": row["last_connected"], "last_disconnected": row["last_disconnected"],
            "online_since": live.connected_at if live else None,
            "platform": row["platform"], "agent_version": row["agent_version"],
            "latest_agent_version": latest_agent_version,
            "is_outdated": bool(latest_agent_version and row["agent_version"] != latest_agent_version),
            "jobs_ok": row["jobs_ok"], "jobs_failed": row["jobs_failed"],
        })
    return out


@app.get("/api/agents")
def api_agents(user: dict[str, str] = Depends(require_dashboard_user)):
    rows = _agent_rows()
    if user["role"] == "admin":
        agent_tokens = {row["agent_id"]: row["agent_token"] for row in store.list_agents()}
        for row in rows:
            row["agent_token"] = agent_tokens[row["agent_id"]]
    by_status: dict[str, int] = defaultdict(int)
    by_location: dict[str, int] = defaultdict(int)
    for r in rows:
        by_status[r["status"]] += 1
        by_location[r["location"] or "Unassigned"] += 1
    active = sum(1 for r in rows if r["state"] == "active")
    tokens = (store.list_user_tokens(user["username"])
              if user["role"] == "user" else store.list_user_tokens())
    return {"generated_at": time.time(), "total": len(rows), "role": user["role"],
            "username": user["username"], "locations": sorted(by_location),
            "latest_agent_version": store.get_latest_agent_version(),
            "summary": {"active": active, "inactive": len(rows) - active,
                        "by_status": by_status, "by_location": by_location,
                        "jobs_ok": sum(r["jobs_ok"] for r in rows),
                        "jobs_failed": sum(r["jobs_failed"] for r in rows),
                        "requests": sum(t["requests"] for t in tokens),
                        "users": len(store.list_users()) if user["role"] == "admin" else 1},
            "agents": rows}


@app.get("/api/agents.csv", response_class=PlainTextResponse)
def api_agents_csv(user: dict[str, str] = Depends(require_dashboard_user)):
    rows = _agent_rows()
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            r = dict(r)
            for k in ("last_seen", "last_connected", "last_disconnected", "online_since"):
                if r[k]:
                    r[k] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[k]))
            w.writerow(r)
    return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=agents.csv"})


@app.get("/api/office-networks")
def api_office_networks(_: str = Depends(require_admin)):
    return store.list_office_networks()


@app.post("/api/office-networks", status_code=201)
def api_add_office_network(
    body: OfficeNetworkCreate,
    _: str = Depends(require_admin_write),
):
    try:
        cidr = store.add_office_network(body.network, body.label.strip())
    except ValueError as exc:
        raise HTTPException(422, f"invalid office network: {exc}") from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "office network already exists") from exc
    office_networks.reload()
    return {"ok": True, "network": cidr}


@app.delete("/api/office-networks")
def api_remove_office_network(
    network: str = Query(..., min_length=1, max_length=64),
    _: str = Depends(require_admin_write),
):
    try:
        removed = store.remove_office_network(network)
    except ValueError as exc:
        raise HTTPException(422, f"invalid office network: {exc}") from exc
    if not removed:
        raise HTTPException(404, "office network not found")
    office_networks.reload()
    return {"ok": True}


@app.post("/api/agents", status_code=201)
def api_add_agent(body: AgentCreate, user: str = Depends(require_admin_write)):
    agent_id = body.agent_id.strip()
    owner = body.owner.strip()
    if not agent_id:
        raise HTTPException(422, "agent_id must not be blank")
    if body.token is not None and not body.token.strip():
        raise HTTPException(422, "token must not be blank")
    try:
        token = store.add_agent(agent_id, body.label.strip(), owner, body.token or "")
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "agent_id or token already exists") from exc
    store.log_event(agent_id, "registered_by", user)
    return {"ok": True, "agent_id": agent_id, "token": token}


@app.get("/api/events")
def api_events(limit: int = 100, agent_id: Optional[str] = None,
               user: dict[str, str] = Depends(require_dashboard_user)):
    limit = max(1, min(limit, 1000))
    # if user["role"] == "user":
    #     return store.recent_events_for_owner(user["username"], limit, agent_id)
    return store.recent_events(limit, agent_id)


def _usage_timestamps(start_date: Optional[date], end_date: Optional[date]):
    if start_date and end_date and start_date > end_date:
        raise HTTPException(422, "start_date must be on or before end_date")
    start_ts = (datetime.combine(start_date, datetime_time.min, timezone.utc).timestamp()
                if start_date else None)
    end_ts = (datetime.combine(end_date + timedelta(days=1), datetime_time.min,
                               timezone.utc).timestamp()
              if end_date else None)
    return start_ts, end_ts


@app.get("/api/usage/logs")
def api_usage_logs(
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    domain: Optional[str] = Query(None, max_length=253),
    service: Optional[Literal["requests", "selenium", "nodriver", "playwright"]] = None,
    agent_id: Optional[str] = Query(None, max_length=128),
    result: Optional[Literal["success", "failure"]] = None,
    status_code: Optional[int] = Query(None, ge=100, le=599),
    client_id: Optional[str] = Query(None, max_length=80),
    sort_order: Literal["asc", "desc"] = "desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
    snapshot_id: Optional[int] = Query(None, ge=0),
    user: dict[str, str] = Depends(require_dashboard_user),
):
    """One page of request logs. Users see only their own; admins see everyone's.

    snapshot_id pins the result set to the logs that existed when browsing started,
    so later pages don't shift while new requests keep arriving. Omit it for live data.
    """
    start_ts, end_ts = _usage_timestamps(start_date, end_date)
    owner = user["username"] if user["role"] == "user" else None
    filters = dict(domain=domain, service=service, agent_id=agent_id, result=result,
                   status_code=status_code, client_id=client_id)
    latest_id = store.max_usage_log_id()
    snapshot = latest_id if snapshot_id is None else min(snapshot_id, latest_id)

    total = store.count_usage_logs(owner, start_ts, end_ts, max_id=snapshot, **filters)
    pages = max(1, -(-total // page_size))
    page = min(page, pages)
    logs = store.list_usage_logs(owner, start_ts, end_ts, limit=page_size,
                                 offset=(page - 1) * page_size, sort_order=sort_order,
                                 max_id=snapshot, **filters)
    newer = (store.count_usage_logs(owner, start_ts, end_ts, min_id=snapshot + 1, **filters)
             if snapshot < latest_id else 0)
    return {"logs": logs, "total": total, "page": page, "page_size": page_size, "pages": pages,
            "snapshot_id": snapshot, "newer": newer}


@app.get("/api/usage/summary")
def api_usage_summary(
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    domain: Optional[str] = Query(None, max_length=253),
    service: Optional[Literal["requests", "selenium", "nodriver", "playwright"]] = None,
    agent_id: Optional[str] = Query(None, max_length=128),
    result: Optional[Literal["success", "failure"]] = None,
    status_code: Optional[int] = Query(None, ge=100, le=599),
    client_id: Optional[str] = Query(None, max_length=80),
    user: dict[str, str] = Depends(require_dashboard_user),
):
    start_ts, end_ts = _usage_timestamps(start_date, end_date)
    owner = user["username"] if user["role"] == "user" else None
    return store.usage_summary(
        owner, start_ts, end_ts, domain=domain, service=service, agent_id=agent_id,
        result=result, status_code=status_code, client_id=client_id
    )


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._@-]+$")
    email: str = Field(min_length=3, max_length=254,
                       pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=12, max_length=256)


class UserPasswordReset(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class UserEmailUpdate(BaseModel):
    email: str = Field(min_length=3, max_length=254,
                       pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ForgotPassword(BaseModel):
    email: str = Field(min_length=3, max_length=254,
                       pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class PasswordReset(BaseModel):
    token: str = Field(min_length=20, max_length=128)
    password: str = Field(min_length=12, max_length=256)


class UserTokenCreate(BaseModel):
    client_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    location: Optional[str] = Field(None, max_length=120)


@app.get("/api/users")
def api_users(_: str = Depends(require_admin)):
    tokens = _tokens_with_quota(store.list_user_tokens())
    by_user: dict[str, list] = defaultdict(list)
    for token in tokens:
        by_user[token["owner"]].append(token)
    return [{"username": user["username"], "enabled": bool(user["enabled"]),
             "email": user["email"], "created_at": user["created_at"],
             "agents": user["agents"],
             "tokens": by_user[user["username"]]}
            for user in store.list_users()]


@app.get("/api/me/tokens")
def api_my_tokens(user: dict[str, str] = Depends(require_dashboard_user)):
    if user["role"] != "user":
        raise HTTPException(400, "this endpoint is for user accounts")
    return _tokens_with_quota(store.list_user_tokens(user["username"]))


@app.post("/api/users")
def api_create_user(body: UserCreate, user: str = Depends(require_admin_write)):
    try:
        store.add_user(body.username, body.email, body.password)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "user name or email already exists")
    store.log_event(None, "user_created", f"{body.username} by {user}")
    return {"ok": True, "username": body.username}


@app.post("/api/users/{username}/password")
def api_reset_user_password(username: str, body: UserPasswordReset,
                            user: str = Depends(require_admin_write)):
    if not store.set_user_password(username, body.password):
        raise HTTPException(404, "no such user")
    store.log_event(None, "user_password_reset", f"{username} by {user}")
    return {"ok": True}


@app.post("/api/users/{username}/email")
def api_update_user_email(username: str, body: UserEmailUpdate,
                          user: str = Depends(require_admin_write)):
    try:
        updated = store.set_user_email(username, body.email)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "email address already belongs to another user")
    if not updated:
        raise HTTPException(404, "no such user")
    store.log_event(None, "user_email_updated", f"{username} by {user}")
    return {"ok": True}


@app.post("/api/users/{username}/tokens")
def api_create_user_token(username: str, body: UserTokenCreate,
                          user: dict[str, str] = Depends(require_dashboard_write)):
    if user["role"] != "admin":
        raise HTTPException(403, "administrator account required")
    return _create_user_token(username, body, user["username"])


@app.post("/api/users/{username}/tokens/{client_id}/rotate")
async def api_rotate_user_token(username: str, client_id: str,
                                user: dict[str, str] = Depends(require_dashboard_write)):
    if user["role"] != "admin":
        raise HTTPException(403, "administrator account required")
    return await _rotate_user_token(username, client_id, user["username"])


def _create_user_token(username: str, body: UserTokenCreate, actor: str) -> dict:
    account = store.get_user(username)
    if not account:
        raise HTTPException(404, "no such user")
    if not account["enabled"]:
        raise HTTPException(409, "cannot create a token for a disabled user")
    if body.location and not store.location_exists(body.location):
        raise HTTPException(422, "location is not assigned to an agent")
    try:
        token = store.add_user_token(username, body.client_id, body.location or None)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "token name already exists")
    store.log_event(None, "user_token_created",
                    f"{body.client_id} for {username} ({body.location or 'all locations'}) by {actor}")
    return {"client_id": body.client_id, "token": token, "owner": username,
            "location": body.location or None, "daily_limit": DEFAULT_DAILY_FETCH_LIMIT}


async def _rotate_user_token(username: str, client_id: str, actor: str) -> dict:
    if not store.get_user(username):
        raise HTTPException(404, "no such user")
    result = store.rotate_user_token(username, client_id)
    if not result:
        raise HTTPException(404, "no such user token")
    token, sessions = result
    by_agent: dict[str, list[str]] = defaultdict(list)
    for session in sessions:
        by_agent[session["agent_id"]].append(session["session_id"])
    for agent_id, session_ids in by_agent.items():
        await _notify_session_deletions(agent_id, session_ids, "client token rotated")
    store.log_event(None, "user_token_rotated", f"{client_id} for {username} by {actor}")
    return {"client_id": client_id, "token": token, "owner": username}


@app.post("/api/me/tokens")
def api_create_my_token(body: UserTokenCreate,
                        user: dict[str, str] = Depends(require_dashboard_write)):
    if user["role"] != "user":
        raise HTTPException(400, "this endpoint is for user accounts")
    return _create_user_token(user["username"], body, user["username"])


@app.post("/api/me/tokens/{client_id}/rotate")
async def api_rotate_my_token(client_id: str,
                              user: dict[str, str] = Depends(require_dashboard_write)):
    if user["role"] != "user":
        raise HTTPException(400, "this endpoint is for user accounts")
    return await _rotate_user_token(user["username"], client_id, user["username"])


@app.delete("/api/me/tokens/{client_id}")
async def api_delete_my_token(client_id: str,
                              user: dict[str, str] = Depends(require_dashboard_write)):
    if user["role"] != "user":
        raise HTTPException(400, "this endpoint is for user accounts")
    sessions = store.delete_user_token(user["username"], client_id)
    if sessions is None:
        raise HTTPException(404, "no such token")
    by_agent: dict[str, list[str]] = defaultdict(list)
    for session in sessions:
        by_agent[session["agent_id"]].append(session["session_id"])
    for agent_id, session_ids in by_agent.items():
        await _notify_session_deletions(agent_id, session_ids, "client token deleted")
    store.log_event(None, "user_token_deleted", f"{client_id} for {user['username']}")
    return {"ok": True}


@app.post("/api/users/{username}/enabled/{action}")
def api_user_action(username: str, action: str,
                    user: str = Depends(require_admin_write)):
    if action not in ("enable", "disable"):
        raise HTTPException(404)
    if not store.set_user_enabled(username, action == "enable"):
        raise HTTPException(404, "no such user")
    store.log_event(None, f"user_{action}d", f"{username} by {user}")
    return {"ok": True}


class DailyLimitUpdate(BaseModel):
    daily_limit: int = Field(ge=0, le=1_000_000)


@app.post("/api/users/{username}/tokens/{client_id}/daily-limit")
def api_set_token_daily_limit(username: str, client_id: str, body: DailyLimitUpdate,
                              user: str = Depends(require_admin_write)):
    # Declared before the generic /{action} route below so this path matches first.
    if not store.set_user_token_daily_limit(username, client_id, body.daily_limit):
        raise HTTPException(404, "no such user token")
    store.log_event(None, "user_token_limit_changed",
                    f"{client_id} for {username}: {body.daily_limit} per day by {user}")
    return {"ok": True, "client_id": client_id, "daily_limit": body.daily_limit}


@app.post("/api/users/{username}/tokens/{client_id}/{action}")
def api_user_token_action(username: str, client_id: str, action: str,
                          user: str = Depends(require_admin_write)):
    if action not in ("enable", "disable"):
        raise HTTPException(404)
    if not store.set_user_token_enabled(username, client_id, action == "enable"):
        raise HTTPException(404, "no such user token")
    store.log_event(None, f"user_token_{action}d", f"{client_id} for {username} by {user}")
    return {"ok": True}


class DashboardLogin(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@app.get("/login", response_class=HTMLResponse)
def dashboard_login():
    return HTMLResponse(DASHBOARD_LOGIN_HTML.read_text(encoding="utf-8"),
                        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})


@app.post("/forgot-password")
def forgot_password(body: ForgotPassword, request: Request):
    _throttle_password_reset(_ip(request))
    try:
        mail_settings = _password_reset_mail_settings()
    except RuntimeError as exc:
        log.error("password reset email is unavailable: %s", exc)
        raise HTTPException(503, "password reset email is not configured") from exc

    account = store.user_by_email(body.email)
    if account and account["enabled"]:
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + PASSWORD_RESET_TTL_SEC
        if store.create_password_reset(account["username"], token, expires_at):
            try:
                _send_password_reset_email(account["email"], token, mail_settings)
            except (OSError, RuntimeError, smtplib.SMTPException, ValueError) as exc:
                store.delete_password_reset(token)
                log.error("password reset email delivery failed (%s)", type(exc).__name__)
                raise HTTPException(503, "password reset email could not be sent") from exc
    return {"ok": True, "message": "If that account exists, a reset link has been sent."}


@app.post("/reset-password")
def reset_password(body: PasswordReset, request: Request):
    _throttle_password_reset(_ip(request))
    if not store.consume_password_reset(body.token, body.password):
        raise HTTPException(400, "invalid or expired password reset link")
    return {"ok": True}


@app.post("/login")
def dashboard_login_submit(body: DashboardLogin, request: Request):
    ip = _ip(request)
    _throttle(ip)
    if store.admin_ok(body.username, body.password):
        role = "admin"
    elif store.user_ok(body.username, body.password):
        role = "user"
    else:
        _record_fail(ip, "dashboard")
        raise HTTPException(401, "invalid username or password")

    token = secrets.token_urlsafe(32)
    store.create_dashboard_session(token, body.username, role,
                                   time.time() + DASHBOARD_SESSION_TTL_SEC)
    response = JSONResponse({"ok": True, "username": body.username, "role": role})
    response.set_cookie(
        "dashboard_session", token, max_age=DASHBOARD_SESSION_TTL_SEC,
        httponly=True, secure=request.url.scheme == "https",
        samesite="strict", path="/",
    )
    return response


@app.post("/logout")
def dashboard_logout(request: Request):
    if request.headers.get("x-requested-with") != "dashboard":
        raise HTTPException(403, "missing X-Requested-With header")
    token = request.cookies.get("dashboard_session")
    if token:
        store.delete_dashboard_session(token)
    response = Response(status_code=204)
    response.delete_cookie("dashboard_session", path="/", httponly=True,
                           secure=request.url.scheme == "https", samesite="strict")
    return response


@app.post("/api/agents/{agent_id}/{action}")
async def api_agent_action(agent_id: str, action: str, user: str = Depends(require_admin_write)):
    if action not in ("enable", "disable"):
        raise HTTPException(404)
    if not store.set_agent_enabled(agent_id, action == "enable"):
        raise HTTPException(404, "no such agent")
    store.log_event(agent_id, f"{action}d_by", user)
    live = registry.agents.get(agent_id)
    if action == "disable" and live:
        try:
            await live.ws.close(code=4403)
        except Exception:
            pass
    return {"ok": True}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not _dashboard_user(request):
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse(DASHBOARD_HTML.read_text(encoding="utf-8"),
                        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})


@app.get("/healthz")
def healthz():
    return {"ok": True}
