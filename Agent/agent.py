"""
Fetch agent (v2) - runs on an employee's machine and uses its home broadband as egress.

Started at logon by Task Scheduler (see install_agent.ps1). Recovery layers:
  1. inside the process: reconnect with backoff after any network drop; detect
     sleep/hibernate/resume and reconnect immediately; restart a crashed browser
  2. the process itself: an outer loop restarts the event loop if it ever dies
  3. the OS: Task Scheduler relaunches it at logon, at unlock and every 5 minutes
     if it isn't running (a single-instance lock prevents duplicates)

Config: agent.json next to this file (or AGENT_CONFIG=path); env vars override.
    {"coordinator_url": "wss://crawl.yourco.com/agent", "agent_token": "agt_...",
     "max_concurrency": 2, "active_hours": "", "daily_mb_cap": 500, "allow_on_battery": false}
Pause switch: create ~/.fetch-agent-pause (delete it to resume).

Scrape method per job: job["method"] = requests | selenium | nodriver | playwright
(same four methods as main.py). Old jobs still work: render=true -> playwright, else requests.
Optional job fields: headers, proxy, http_method, json or data (POST body), wait_seconds, wait_until,
wait_for_selector, timeout, session_id, session_action (create | reuse).
Result fields match main.py's FetchResponse: service, status (success/blocked/error), status_code,
tat_ms, elapsed (seconds), fetched_ip, url, final_url, blocked, block_message, error, content_length, content,
content_type, content_encoding ("json" | "text" | "base64"), truncated, request  (+ type, job_id, ok, method,
filename). Binary files are base64 in `content`. Job field include_content=false drops the content.
"""
import asyncio
import base64
import datetime as dt
import ipaddress
import json
import logging
import mimetypes
import os
import re
import platform
import random
import shutil
import socket
import sys
import tempfile
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
import traceback
from urllib.parse import urlparse

FROZEN = getattr(sys, "frozen", False)          # True when running as the packaged fetch-agent.exe
BASE_DIR = Path(sys.executable).parent if FROZEN else Path(__file__).resolve().parent
VERSION_PATH = (Path(getattr(sys, "_MEIPASS", BASE_DIR)) / "agent_version.txt"
                if FROZEN else Path(__file__).with_name("agent_version.txt"))
try:
    AGENT_VERSION = VERSION_PATH.read_text(encoding="ascii").strip()
except OSError as exc:
    raise RuntimeError(f"agent version file is unavailable: {VERSION_PATH}") from exc
if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", AGENT_VERSION):
    raise RuntimeError(f"invalid agent version in {VERSION_PATH}: {AGENT_VERSION!r}")

# Packaged build: Chromium is bundled inside the package (built with PLAYWRIGHT_BROWSERS_PATH=0).
# Point Playwright at it so the employee machine needs no separate browser download.
if FROZEN:
    _bundled = Path(getattr(sys, "_MEIPASS", BASE_DIR)) / "playwright" / "driver" / "package" / ".local-browsers"
    if _bundled.exists():
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "0")


# --------------------------------------------------------------------------- config
def _load_config() -> dict:
    path = Path(os.getenv("AGENT_CONFIG", BASE_DIR / "agent.json"))
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8-sig"))   # -sig: PowerShell writes a BOM
    return {}


_CFG = _load_config()


def conf(key: str, default):
    val = os.getenv(key.upper(), _CFG.get(key, default))
    if isinstance(default, bool):
        return str(val).lower() in ("1", "true", "yes")
    return type(default)(val) if default is not None and val is not None else val


COORDINATOR_URL = conf("coordinator_url", "ws://localhost:8000/agent")
AGENT_TOKEN = conf("agent_token", "")
MAX_CONCURRENCY = conf("max_concurrency", 2)
ACTIVE_HOURS = conf("active_hours", "")
DAILY_MB_CAP = conf("daily_mb_cap", 500.0)
ALLOW_ON_BATTERY = conf("allow_on_battery", False)
MAX_BODY_BYTES = conf("max_body_mb", 25) * 1024 * 1024   # larger text is truncated, larger files refused
LOCK_PORT = conf("lock_port", 47831)
PAUSE_FILE = Path.home() / ".fetch-agent-pause"
EGRESS_CHECK_URL = "https://api.ipify.org"
HEARTBEAT_SEC = 15
SLEEP_GAP_SEC = 45            # a heartbeat gap this long means the machine was asleep


# --------------------------------------------------------------------------- logging
def _setup_logging() -> logging.Logger:
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(exist_ok=True)
    handlers = [RotatingFileHandler(log_dir / "agent.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")]
    if sys.stderr is not None:          # pythonw.exe has no console
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s")
    return logging.getLogger("agent")


log = _setup_logging()
_JITTER = random.SystemRandom()   # reconnect jitter, drawn from the OS CSPRNG


def acquire_single_instance_lock():
    """Bind a localhost port as a lock. The OS frees it if the process dies."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", LOCK_PORT))
        s.listen(1)
    except OSError:
        return None
    return s


# imports that may be missing are deferred until after logging is up
import websockets  # noqa: E402
from curl_cffi.requests import AsyncSession  # noqa: E402

try:
    import psutil
except ImportError:
    psutil = None


# --------------------------------------------------------------------------- safety
def _is_private_literal(host: str) -> bool:
    if host in ("localhost", "") or host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


async def is_public_target(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname or _is_private_literal(p.hostname):
        return False
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(p.hostname, None)
    except OSError:
        return False
    return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


class DailyStats:
    def __init__(self):
        self.day, self.bytes = dt.date.today(), 0

    def add(self, n: int):
        if dt.date.today() != self.day:
            self.day, self.bytes = dt.date.today(), 0
        self.bytes += n

    def mb_today(self) -> float:
        return 0.0 if dt.date.today() != self.day else self.bytes / 1_048_576


def pause_reason(stats: DailyStats):
    if PAUSE_FILE.exists():
        return "paused by user"
    if ACTIVE_HOURS:
        start, end = (int(x) for x in ACTIVE_HOURS.split("-"))
        if not start <= dt.datetime.now().hour < end:
            return "outside active hours"
    if psutil and not ALLOW_ON_BATTERY:
        batt = psutil.sensors_battery()
        if batt is not None and not batt.power_plugged:
            return "on battery"
    if stats.mb_today() >= DAILY_MB_CAP:
        return "daily data cap reached"
    return None


BLOCK_STATUS = {
    401: "Unauthorized",
    403: "Forbidden",
    407: "Proxy authentication required",
    429: "Too many requests (rate limited)",
    451: "Unavailable for legal reasons",
}

MARKERS = {
    "Cloudflare challenge": [
        "just a moment...", "cf-chl", "challenge-platform",
        "attention required! | cloudflare", "cf-browser-verification",
    ],
    "CAPTCHA required": [
        "g-recaptcha", "h-captcha", "hcaptcha.com/1/api",
        "please verify you are a human", "are you a robot",
    ],
    "PerimeterX": ["px-captcha", "press & hold to confirm"],
    "DataDome": ["datadome", "captcha-delivery.com"],
    "Imperva/Incapsula": ["incapsula incident id", "_incapsula_resource"],
    "Akamai": ["errors.edgesuite.net", "reference #18."],
    "Generic bot protection": [
        "access denied", "unusual traffic from your computer network",
        "request blocked", "you have been blocked", "automated access", "bot detected",
    ],
}


def detect_block(status_code, content):
    """Return a human-readable blocking message, or None if not blocked (same as main.py)."""
    reasons = []
    if status_code in BLOCK_STATUS:
        reasons.append(f"HTTP {status_code} {BLOCK_STATUS[status_code]}")
    text = content or ""
    if text and ((status_code or 0) >= 400 or len(text) < 30_000):
        head = text[:30_000].lower()
        for name, needles in MARKERS.items():
            hit = next((n for n in needles if n in head), None)
            if hit:
                reasons.append(f"{name} detected (matched '{hit}')")
                break
    if status_code == 503 and not any("detected" in r for r in reasons):
        return None
    return "; ".join(reasons) if reasons else None


# --------------------------------------------------------------------------- content types
MAGIC = (  # signature -> type, used when the server sends no or a generic content type
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),
    (b"PK\x03\x04", "application/zip"),          # also xlsx/docx/pptx; refined by file extension
    (b"\xd0\xcf\x11\xe0", "application/vnd.ms-excel"),  # legacy xls/doc
)
GENERIC_TYPES = ("", "application/octet-stream", "binary/octet-stream", "application/download",
                 "application/force-download", "application/x-download")


def _mime(content_type: str) -> str:
    return (content_type or "").split(";")[0].strip().lower()


def is_json_type(content_type: str) -> bool:
    m = _mime(content_type)
    return m.endswith("/json") or m.endswith("+json")


def is_text_type(content_type: str):
    """True / False from the content type, or None when it doesn't say."""
    m = _mime(content_type)
    if m in GENERIC_TYPES:
        return None
    if m in ("text/csv", "application/csv"):
        return False
    return (m.startswith("text/") or is_json_type(m) or m in ("application/xml", "text/xml")
            or m.endswith("+xml") or m in ("application/javascript", "text/javascript")
            or m.endswith("x-www-form-urlencoded"))


def resolve_type(content_type: str, body: bytes, url: str, filename: str = None):
    """Return (content_type, is_text), sniffing the bytes when the server's type is missing or generic."""
    verdict = is_text_type(content_type)
    if verdict is not None:
        return content_type, verdict
    name = filename or urlparse(url).path
    guessed = mimetypes.guess_type(name)[0]
    for sig, mime in MAGIC:
        if body.startswith(sig):
            if mime == "application/zip" and guessed and guessed.startswith("application/vnd.openxmlformats"):
                mime = guessed                       # .xlsx / .docx / .pptx are zip files
            return mime, False
    if guessed:
        return guessed, bool(is_text_type(guessed))
    sample = body[:4096]
    if b"\x00" in sample:
        return "application/octet-stream", False
    try:
        sample.decode("utf-8")
        return "text/plain; charset=utf-8", True
    except UnicodeDecodeError:
        return "application/octet-stream", False


def filename_from(disposition: str):
    if not disposition:
        return None
    m = re.search(r"filename\*\s*=\s*[^']*'[^']*'([^;]+)", disposition, re.I)
    if m:
        from urllib.parse import unquote
        return unquote(m.group(1).strip().strip('"'))
    m = re.search(r'filename\s*=\s*"?([^";]+)"?', disposition, re.I)
    return m.group(1).strip() if m else None


# --------------------------------------------------------------------------- fetchers
# Four scrape services, same behaviour as main.py: requests, selenium, nodriver, playwright.
# Every service returns the same dict:
#   {status, final_url, content_type, filename, ip, request, truncated, and either
#    "text" (decoded text) or "body" (raw bytes of a binary file)}
# handle_job() then builds the main.py-style response (text, or base64 for binary files).
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
CHROME_ARGS = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--window-size=1366,768"]
SCRAPE_SERVICES = ("requests", "selenium", "nodriver", "playwright")


def _is_binary_type(content_type: str) -> bool:
    """True when the content type says 'this is a file, not a page' (pdf, xlsx, image, octet-stream...)."""
    m = _mime(content_type)
    return bool(m) and is_text_type(m) is not True


def _charset(content_type: str):
    m = re.search(r"charset=\s*\"?([\w\-]+)", content_type or "", re.I)
    return m.group(1) if m else None


def make_out(status, final_url, content_type, raw: bytes, *, filename=None, encoding=None,
             ip=None, request_info=None, truncated=False) -> dict:
    """Turn raw response bytes into the common result dict (text -> str, binary -> bytes)."""
    ctype, is_text = resolve_type(content_type or "", raw, final_url or "", filename)
    out = {"status": status, "final_url": final_url, "content_type": ctype, "filename": filename,
           "ip": ip, "request": request_info, "truncated": truncated, "size": len(raw)}
    if is_text:
        try:
            text = raw.decode(encoding or _charset(ctype) or "utf-8", "replace")
        except LookupError:                      # unknown charset name
            text = raw.decode("utf-8", "replace")
        out["text"] = text
        if is_json_type(ctype):
            out["json"] = json.loads(text)
    else:
        out["body"] = raw
    return out


def oversized_out(status, url, content_type, size, *, filename=None, ip=None, request_info=None) -> dict:
    """A file bigger than max_body_mb: report its real size, send no content (truncated=True), like main.py."""
    return {"status": status, "final_url": url, "content_type": _mime(content_type) or None,
            "filename": filename, "ip": ip, "request": request_info, "truncated": True,
            "size": size, "body": None}


def _wait_for_download(folder: str, timeout: float):
    """Wait for a finished download (no .crdownload / .tmp files) and return its path."""
    end = time.time() + timeout
    while time.time() < end:
        files = [p for p in Path(folder).iterdir() if p.is_file()]
        if files and not any(p.suffix in (".crdownload", ".tmp") for p in files):
            return files[0]
        time.sleep(0.3)
    return None


# ---- requests ------------------------------------------------------------
def _requests_peer_ip(resp):
    try:  # only valid while the stream is still open
        return resp.raw._connection.sock.getpeername()[0]
    except Exception:
        return None


def _serialize_request(r) -> dict:
    body = r.body
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    return {"method": r.method, "url": r.url, "headers": dict(r.headers), "body": body}


def _requests_scrape_sync(job: dict, session=None) -> dict:
    import requests
    headers = {
        "User-Agent": DEFAULT_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        **(job.get("headers") or {}),
    }
    proxy = job.get("proxy")
    proxies = {"http": proxy, "https": proxy} if proxy else None
    http_method = (job.get("http_method") or "GET").upper()
    body = {}
    if http_method == "POST":
        if job.get("json") is not None:
            body["json"] = job["json"]
        elif job.get("data") is not None:
            body["data"] = job["data"]
    if job.get("cookies"):
        body["cookies"] = job["cookies"]
    def scrape(s):
        s.max_redirects = 5
        resp = s.request(http_method, job["url"], headers=headers, proxies=proxies,
                         timeout=job["timeout"],
                         stream=True, allow_redirects=True, **body)
        ip = _requests_peer_ip(resp)                 # grab before the body is consumed
        ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()

        chunks, size, truncated = [], 0, False
        for chunk in resp.iter_content(chunk_size=65536):
            chunks.append(chunk)
            size += len(chunk)
            # if size > MAX_BODY_BYTES:                # stop downloading huge files
            #     truncated = True
            #     break
        resp.close()
        # raw = b"".join(chunks)[:MAX_BODY_BYTES]
        raw = b"".join(chunks)
        return make_out(
            resp.status_code, resp.url, ctype, raw,
            filename=filename_from(resp.headers.get("content-disposition")),
            encoding=resp.encoding if _charset(ctype) else None,
            ip=ip, request_info=_serialize_request(resp.request), truncated=truncated,
        )

    if session is not None:
        return scrape(session)
    with requests.Session() as s:
        return scrape(s)


# ---- selenium ------------------------------------------------------------
def _selenium_document_response(driver):
    """Return (status, ip, content_type, request_info) for the final main-document exchange."""
    status = ip = ctype = None
    request_info = None
    try:
        for entry in driver.get_log("performance"):
            msg = json.loads(entry["message"])["message"]
            method, p = msg.get("method"), msg.get("params", {})
            if method == "Network.requestWillBeSent" and p.get("type") == "Document":
                r = p["request"]                     # overwritten per redirect -> keeps the LAST one
                request_info = {"method": r.get("method"), "url": r.get("url"),
                                "headers": r.get("headers") or {}, "body": r.get("postData")}
            elif method == "Network.responseReceived" and p.get("type") == "Document":
                r = p["response"]
                status = r.get("status")
                ip = r.get("remoteIPAddress")
                headers = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
                ctype = (headers.get("content-type") or r.get("mimeType") or "")
                ctype = ctype.split(";")[0].strip().lower() or None
    except Exception as exc:
        log.debug("could not read selenium performance log: %s: %s", type(exc).__name__, exc)
    return status, ip, ctype, request_info


def _selenium_scrape_sync(job: dict) -> dict:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as SeleniumOptions

    url, timeout = job["url"], job["timeout"]
    wait_seconds = job.get("wait_seconds") or 0
    timeout = timeout + wait_seconds
    download_dir = tempfile.mkdtemp(prefix="sel_dl_")
    opts = SeleniumOptions()
    opts.add_argument("--headless=new")
    for a in CHROME_ARGS:
        opts.add_argument(a)
    opts.add_argument(f"--user-agent={(job.get('headers') or {}).get('User-Agent', DEFAULT_UA)}")
    if job.get("proxy"):
        opts.add_argument(f"--proxy-server={job['proxy']}")
    if os.getenv("CHROME_BIN"):
        opts.binary_location = os.environ["CHROME_BIN"]
    opts.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    opts.add_experimental_option("prefs", {
        "download.default_directory": download_dir,
        "download.prompt_for_download": False,
        "download.directory_upgrade": True,
    })

    driver = webdriver.Chrome(options=opts)
    try:
        driver.set_page_load_timeout(timeout)
        try:
            driver.get(url)
        except Exception as exc:
            # a download can make driver.get error out; the log still has the response
            log.debug("driver.get raised (expected for downloads): %s: %s", type(exc).__name__, exc)
        if job.get("wait_seconds"):
            time.sleep(job["wait_seconds"])

        status, ip, ctype, request_info = _selenium_document_response(driver)

        if _is_binary_type(ctype):
            f = _wait_for_download(download_dir, timeout)    # file download -> raw bytes
            if f is None:
                raise TimeoutError("Download did not complete")
            size = f.stat().st_size
            if size > MAX_BODY_BYTES:
                return oversized_out(status, url, ctype, size, filename=f.name, ip=ip,
                                     request_info=request_info)
            return make_out(status, url, ctype, f.read_bytes(), filename=f.name, ip=ip,
                            request_info=request_info)       # 'data:,' final url is meaningless
        if job.get("wait_for_selector"):
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            WebDriverWait(driver, wait_seconds).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, job["wait_for_selector"])))
        # elif wait_seconds > 0:
        #     time.sleep(wait_seconds)
        raw = driver.page_source.encode("utf-8")
        return make_out(status, driver.current_url, ctype or "text/html", raw, encoding="utf-8",
                        ip=ip, request_info=request_info)
    finally:
        driver.quit()
        shutil.rmtree(download_dir, ignore_errors=True)


class Renderer:
    """Runs the four scrape services. Keeps one shared Playwright browser (restarted on demand)."""

    def __init__(self):
        self.services = []
        for name in SCRAPE_SERVICES:
            try:
                __import__(name)
                self.services.append(name)
            except ImportError:
                pass
        self.methods = list(self.services)
        self.available = "playwright" in self.services      # kept for the old `can_render` flag
        self._pw = self._browser = None
        self._lock = asyncio.Lock()
        self._request_sessions = {}
        self._request_session_locks = {}

    async def scrape(self, service: str, job: dict) -> dict:
        if service not in self.services:
            raise RuntimeError(f"scrape service '{service}' not supported on this agent")
        if service   == "requests":
            session_id = job.get("session_id")
            if session_id:
                action = job.get("session_action")
                if action not in ("create", "reuse"):
                    raise ValueError("invalid requests session action")
                lock = self._request_session_locks.setdefault(session_id, asyncio.Lock())
                async with lock:
                    session = self._request_sessions.get(session_id)
                    if action == "create":
                        if session is None:
                            import requests
                            session = requests.Session()
                            self._request_sessions[session_id] = session
                    elif session is None:
                        raise RuntimeError("requests session is unavailable on this agent")
                    return await asyncio.to_thread(_requests_scrape_sync, job, session)
            return await asyncio.to_thread(_requests_scrape_sync, job)
        if job.get("session_id"):
            raise ValueError("sessions are only supported by the requests service")
        if service == "selenium":
            return await asyncio.to_thread(_selenium_scrape_sync, job)
        if service   == "nodriver":
            return await self._nodriver(job)
        return await self._playwright(job)

    async def delete_request_sessions(self, session_ids: list[str]):
        for session_id in session_ids:
            if not isinstance(session_id, str):
                continue
            lock = self._request_session_locks.setdefault(session_id, asyncio.Lock())
            async with lock:
                session = self._request_sessions.pop(session_id, None)
                if session is not None:
                    await asyncio.to_thread(session.close)

    async def clear_request_sessions(self):
        await self.delete_request_sessions(list(self._request_sessions))
        self._request_session_locks.clear()

    # ---- playwright ------------------------------------------------------
    async def _ensure(self):
        async with self._lock:
            if self._browser and self._browser.is_connected():
                return
            from playwright.async_api import async_playwright
            if self._pw is None:
                self._pw = await async_playwright().start()
            log.info("starting headless browser")
            self._browser = await self._pw.chromium.launch(headless=True)

    async def reset(self):
        """Called after resume from sleep: a browser that slept is often unusable."""
        async with self._lock:
            try:
                if self._browser:
                    await self._browser.close()
            except Exception as exc:
                log.debug("error closing browser during reset: %s: %s", type(exc).__name__, exc)
            self._browser = None

    async def _route(self, route):
        req = route.request
        if req.resource_type in ("image", "media", "font"):
            return await route.abort()
        if _is_private_literal(urlparse(req.url).hostname or ""):
            return await route.abort()
        await route.continue_()

    async def _playwright(self, job: dict) -> dict:
        from playwright.async_api import Error as PlaywrightError
        await self._ensure()
        url, timeout = job["url"], job["timeout"]
        wait_seconds = job.get("wait_seconds") or 0
        timeout = timeout + wait_seconds
        kwargs = {"user_agent": DEFAULT_UA, "extra_http_headers": job.get("headers") or {},
                  "accept_downloads": True}
        if job.get("proxy"):
            kwargs["proxy"] = {"server": job["proxy"]}
        ctx = await self._browser.new_context(**kwargs)
        try:
            await ctx.route("**/*", self._route)
            page = await ctx.new_page()

            downloads, nav = [], {}
            page.on("download", lambda d: downloads.append(d))

            def on_response(r):
                # overwritten on every redirect hop, so we keep the LAST main-frame response
                if r.request.is_navigation_request() and r.frame == page.main_frame:
                    nav["resp"] = r
            page.on("response", on_response)

            resp, download_started = None, False
            try:
                resp = await page.goto(url, wait_until=job.get("wait_until", "load"),
                                       timeout=timeout * 1000)
            except PlaywrightError as e:
                if "Download is starting" not in str(e):
                    raise
                download_started = True

            wait_s = job.get("wait_seconds") or 0
            # if wait_s and not download_started:
            await page.wait_for_timeout(wait_s * 1000)

            r = nav.get("resp") or resp
            headers = await r.all_headers() if r else {}
            ctype = (headers.get("content-type") or "").split(";")[0].strip().lower() or None
            filename = filename_from(headers.get("content-disposition"))

            request_info = None
            ip = None
            if r:
                rq = r.request
                request_info = {"method": rq.method, "url": rq.url,
                                "headers": await rq.all_headers(), "body": rq.post_data}
                addr = await r.server_addr()
                ip = addr["ipAddress"] if addr else None
            status = r.status if r else None

            if download_started or (ctype is not None and _is_binary_type(ctype)):
                if download_started or downloads:
                    for _ in range(timeout * 10):            # download event can lag slightly
                        if downloads:
                            break
                        await asyncio.sleep(0.1)
                    if not downloads:
                        raise TimeoutError("Download did not start")
                    path = Path(await downloads[0].path())   # waits until the download finishes
                    size = path.stat().st_size
                    filename = filename or downloads[0].suggested_filename
                    if size > MAX_BODY_BYTES:
                        return oversized_out(status, url, ctype, size, filename=filename, ip=ip,
                                             request_info=request_info)
                    raw = await asyncio.to_thread(path.read_bytes)
                else:
                    raw = await r.body()                     # image / pdf rendered inline
                return make_out(status, url, ctype, raw, filename=filename, ip=ip,
                                request_info=request_info)   # page.url is 'about:blank' after a download
            if job.get("wait_for_selector"):
                await page.wait_for_selector(job["wait_for_selector"], timeout=wait_seconds * 1000)
            elif wait_seconds > 0:
                await page.wait_for_timeout(wait_seconds * 1000)
            html = await page.content()
            return make_out(status, page.url, ctype or "text/html", html.encode("utf-8"),
                            encoding="utf-8", ip=ip, request_info=request_info)
        finally:
            await ctx.close()

    # ---- nodriver --------------------------------------------------------
    async def _nodriver(self, job: dict) -> dict:
        import nodriver as uc
        url, timeout = job["url"], job["timeout"]
        wait_seconds = job.get("wait_seconds") or 0
        timeout = timeout + wait_seconds
        browser = None
        download_dir = tempfile.mkdtemp(prefix="nd_dl_")
        cap: dict = {}
        try:
            args = [*CHROME_ARGS, f"--user-agent={DEFAULT_UA}"]
            if job.get("proxy"):
                args.append(f"--proxy-server={job['proxy']}")
            browser = await uc.start(headless=True, sandbox=False, browser_args=args)
            tab = await browser.get("about:blank")

            async def on_request(ev: uc.cdp.network.RequestWillBeSent):
                if ev.type_ == uc.cdp.network.ResourceType.DOCUMENT:
                    r = ev.request                   # overwritten per redirect -> keeps the last one
                    cap["request"] = {"method": r.method, "url": r.url,
                                      "headers": dict(r.headers), "body": r.post_data}

            async def on_response(ev: uc.cdp.network.ResponseReceived):
                if ev.type_ == uc.cdp.network.ResourceType.DOCUMENT:
                    h = {k.lower(): v for k, v in dict(ev.response.headers).items()}
                    cap.update(
                        status=int(ev.response.status),
                        ip=ev.response.remote_ip_address,
                        request_id=ev.request_id,
                        disposition=h.get("content-disposition"),
                        ctype=(h.get("content-type") or ev.response.mime_type or "")
                              .split(";")[0].strip().lower() or None,
                    )

            tab.add_handler(uc.cdp.network.RequestWillBeSent, on_request)
            tab.add_handler(uc.cdp.network.ResponseReceived, on_response)
            await tab.send(uc.cdp.network.enable())
            await tab.send(uc.cdp.browser.set_download_behavior(
                behavior="allow", download_path=download_dir))
            if job.get("headers"):
                await tab.send(uc.cdp.network.set_extra_http_headers(
                    uc.cdp.network.Headers(job["headers"])))

            try:
                await asyncio.wait_for(tab.get(url), timeout=timeout)
            except Exception:
                if not cap.get("ctype"):
                    raise                            # real failure; if a response was seen, it's a download
            await tab.sleep(max(job.get("wait_seconds") or 0, 1))

            ctype = cap.get("ctype")
            filename = filename_from(cap.get("disposition"))
            if _is_binary_type(ctype):
                try:                                 # inline resources (images, some pdfs)
                    body, b64 = await tab.send(
                        uc.cdp.network.get_response_body(cap["request_id"]))
                    raw = base64.b64decode(body) if b64 else body.encode("utf-8")
                except Exception:                    # downloads (xlsx, pdf, zip): read the saved file
                    f = await asyncio.to_thread(_wait_for_download, download_dir, timeout)
                    if f is None:
                        raise TimeoutError("Download did not complete")
                    size = f.stat().st_size
                    if size > MAX_BODY_BYTES:
                        return oversized_out(cap.get("status"), url, ctype, size,
                                             filename=filename or f.name, ip=cap.get("ip"),
                                             request_info=cap.get("request"))
                    raw = await asyncio.to_thread(f.read_bytes)
                    filename = filename or f.name
                return make_out(cap.get("status"), url, ctype, raw, filename=filename,
                                ip=cap.get("ip"), request_info=cap.get("request"))
            if job.get("wait_for_selector"):
                await tab.wait_for_selector(job["wait_for_selector"], timeout=wait_seconds * 1000)
            # elif wait_seconds > 0:
            #     time.sleep(wait_seconds)
            html = await tab.get_content()
            final_url = await tab.evaluate("window.location.href")
            return make_out(cap.get("status"), final_url, ctype or "text/html", html.encode("utf-8"),
                            encoding="utf-8", ip=cap.get("ip"), request_info=cap.get("request"))
        finally:
            if browser:
                try:
                    browser.stop()
                except Exception as exc:
                    log.debug("error stopping browser: %s: %s", type(exc).__name__, exc)
            shutil.rmtree(download_dir, ignore_errors=True)


# --------------------------------------------------------------------------- connection
class ResumeDetected(Exception):
    pass


def _resolve_ip_sync(url: str):
    try:
        return socket.getaddrinfo(urlparse(url).hostname, None)[0][4][0]
    except Exception:
        return None


async def build_response(service: str, url: str, started: float, out: dict = None, *,
                         error: str = None, include_content: bool = True) -> dict:
    """Same fields and rules as main.py's FetchResponse / build_response."""
    out = out or {}
    status_code = out.get("status")
    final_url = out.get("final_url")
    text, body = out.get("text"), out.get("body")
    size = out.get("size") or 0
    truncated = bool(out.get("truncated"))
    content = encoding = None

    if error is None:
        if "json" in out:                          # JSON: return the parsed value
            if size > MAX_BODY_BYTES:
                truncated = True
            else:
                content, encoding = out["json"], "json"
        elif text is not None:                     # text / HTML: decoded string, cut if huge
            data = text.encode("utf-8", "replace")
            if len(data) > MAX_BODY_BYTES:
                text, truncated = data[:MAX_BODY_BYTES].decode("utf-8", "ignore"), True
            content, encoding = text, "text"
        elif body is not None and not truncated:   # binary: base64 of the raw bytes
            content, encoding = base64.b64encode(body).decode("ascii"), "base64"
        # binary over the cap: content stays None, truncated=True, content_length = real size

    block_msg = None if error else detect_block(status_code, text if encoding in ("text", "json") else None)
    if error:
        status = "error"
    elif block_msg:
        status = "blocked"
    elif status_code is not None and status_code >= 400:
        status, error = "error", f"HTTP {status_code}"
    else:
        status = "success"

    ip = out.get("ip") or await asyncio.to_thread(_resolve_ip_sync, final_url or url)
    elapsed = time.perf_counter() - started          # one measurement for both fields below
    return {
        "service": service,
        "status": status,
        "status_code": status_code,
        "tat_ms": round(elapsed * 1000, 2),
        "elapsed": round(elapsed, 3),                # seconds
        "fetched_ip": ip,
        "url": url,
        "final_url": final_url,
        "blocked": status == "blocked",
        "block_message": block_msg,
        "error": error,
        "content_length": size,
        "content": content if include_content else None,
        "content_type": _mime(out.get("content_type") or "") or None,
        "content_encoding": encoding if include_content else None,
        "truncated": truncated,
        "request": out.get("request"),
        "filename": out.get("filename"),
    }


async def handle_job(ws, send_lock, sem, session, renderer, stats, job):
    async with sem:
        started, url = time.perf_counter(), job["url"]
        service = job.get("service") or ("playwright" if job.get("render") else "requests")
        include = job.get("include_content", True)
        try:
            reason = pause_reason(stats)
            if reason:
                raise RuntimeError(f"agent paused: {reason}")
            if not await is_public_target(url):
                raise ValueError("target not allowed (non-public address)")
            out = await renderer.scrape(service, job)
            resp = await build_response(service, url, started, out, include_content=include)
            stats.add(resp["content_length"])
            ok = True
        except Exception as e:
            print(traceback.format_exc())
            resp = await build_response(service, url, started, error=f"{type(e).__name__}: {e}")
            ok = False
        res = {"type": "result", "job_id": job["job_id"], "ok": ok, "service": service, **resp}
        log.info("job %s %s [%s] -> %s", job["job_id"][:8], url, service,
                 resp["status_code"] or resp["error"])
        try:
            async with send_lock:
                await ws.send(json.dumps(res))
        except websockets.ConnectionClosed:
            pass


async def heartbeat(ws, send_lock, session, stats):
    egress_ip, last_check, last_beat = None, 0.0, time.time()
    while True:
        now = time.time()
        if now - last_beat > SLEEP_GAP_SEC:
            # wall clock jumped: system slept/hibernated. The socket is almost certainly dead
            # even if it looks open, so drop it and reconnect right away.
            raise ResumeDetected(f"clock gap {now - last_beat:.0f}s")
        last_beat = now
        if now - last_check > 600:
            try:
                txt = (await session.get(EGRESS_CHECK_URL, timeout=10)).text.strip()
                egress_ip = str(ipaddress.ip_address(txt))
            except Exception as exc:
                log.debug("egress IP check failed: %s: %s", type(exc).__name__, exc)
            last_check = now
        reason = pause_reason(stats)
        async with send_lock:
            await ws.send(json.dumps({"type": "heartbeat", "paused": reason is not None,
                                      "pause_reason": reason, "egress_ip": egress_ip,
                                      "mb_today": round(stats.mb_today(), 1)}))
        await asyncio.sleep(HEARTBEAT_SEC)


async def serve_connection(ws, session, renderer, stats):
    await ws.send(json.dumps({"type": "hello", "token": AGENT_TOKEN, "version": AGENT_VERSION,
                              "can_render": renderer.available, "methods": renderer.methods,
                              "max_concurrency": MAX_CONCURRENCY,
                              "platform": platform.platform()}))
    send_lock, sem = asyncio.Lock(), asyncio.Semaphore(MAX_CONCURRENCY)
    hb = asyncio.create_task(heartbeat(ws, send_lock, session, stats))
    jobs: set[asyncio.Task] = set()

    async def reader():
        async for raw in ws:
            msg = json.loads(raw)
            if msg.get("type") == "job":
                t = asyncio.create_task(handle_job(ws, send_lock, sem, session, renderer, stats, msg))
                jobs.add(t)
                t.add_done_callback(jobs.discard)
            elif msg.get("type") == "delete_sessions":
                t = asyncio.create_task(renderer.delete_request_sessions(msg.get("session_ids") or []))
                jobs.add(t)
                t.add_done_callback(jobs.discard)

    rd = asyncio.create_task(reader())
    try:
        done, _ = await asyncio.wait({hb, rd}, return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            t.result()   # re-raise ResumeDetected / ConnectionClosed
    finally:
        for t in (hb, rd, *jobs):
            t.cancel()
        await asyncio.gather(hb, rd, *jobs, return_exceptions=True)
        await renderer.clear_request_sessions()


async def main():
    if not AGENT_TOKEN:
        log.error("agent_token is not configured; exiting")
        sys.exit(2)
    renderer, stats, backoff = Renderer(), DailyStats(), 1
    async with AsyncSession() as session:
        while True:
            try:
                async with websockets.connect(COORDINATOR_URL, open_timeout=15, ping_interval=20,
                                              ping_timeout=20, close_timeout=5, max_size=None) as ws:
                    log.info("connected to %s", COORDINATOR_URL)
                    backoff = 1
                    await serve_connection(ws, session, renderer, stats)
            except ResumeDetected as e:
                log.info("resume from sleep detected (%s); reconnecting now", e)
                await renderer.reset()
                backoff = 1
                continue
            except websockets.ConnectionClosed as e:
                code = e.rcvd.code if e.rcvd else None
                if code in (4401, 4403):
                    # bad/revoked token or disabled by admin: don't hammer the server
                    log.error("coordinator refused this agent (code %s); retrying in 5 min", code)
                    await asyncio.sleep(300)
                    continue
                log.warning("connection closed (code %s)", code)
            except Exception as e:
                log.warning("connection failed: %s: %s", type(e).__name__, e)
            delay = backoff + _JITTER.uniform(0, backoff / 2)
            log.info("reconnecting in %.1fs", delay)
            await asyncio.sleep(delay)
            backoff = min(backoff * 2, 30)


def run_forever():
    lock = acquire_single_instance_lock()
    if lock is None:
        log.info("another agent instance is already running; exiting")
        return
    log.info("fetch agent %s starting (pid %s)", AGENT_VERSION, os.getpid())
    while True:
        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            break
        except SystemExit:
            raise
        except BaseException:
            log.exception("agent crashed; restarting in 10s")
            time.sleep(10)


if __name__ == "__main__":
    run_forever()
