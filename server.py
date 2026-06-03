"""
OneSpan annotation server — with per-annotator authentication.

Auth model:
  - Users stored in users.json as bcrypt hashes
  - Sessions stored in sessions.json (server-side, httponly cookies)
  - Admin role has full access + admin panel
  - Each annotator can only access datasets they've been granted

Environment variables:
    PORT             Port to listen on            (default: 8765)
    DATA_FILE        Annotation data              (default: dataset.json)
    USERS_FILE       User accounts                (default: users.json)
    SESSIONS_FILE    Active sessions              (default: sessions.json)
    HTML_FILE        Tool HTML                    (default: index.html)
    ADMIN_PASSWORD   Initial admin password       (default: spann3r$)
                     Change via the admin UI after first login.
"""

import json, os, shutil, asyncio, secrets, hashlib, time
from datetime import datetime, timezone
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response, Cookie
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PORT          = int(os.environ.get("PORT", 8765))
DATA_FILE     = Path(os.environ.get("DATA_FILE",     "dataset.json"))
USERS_FILE    = Path(os.environ.get("USERS_FILE",    "users.json"))
SESSIONS_FILE = Path(os.environ.get("SESSIONS_FILE", "sessions.json"))
TRACKING_FILE = Path(os.environ.get("TRACKING_FILE", "tracking.json"))
SETTINGS_FILE  = Path(os.environ.get("SETTINGS_FILE",  "settings.json"))
DEMO_DATA_FILE = Path(os.environ.get("DEMO_DATA_FILE", "demo_dataset.json"))

DEMO_MODE  = os.environ.get("DEMO_MODE", "false").lower() in ("true", "1", "yes")
DEMO_TOKEN = "demo-session-token-onespan"
HTML_FILE     = Path(os.environ.get("HTML_FILE",     "index.html"))
ADMIN_PASSWORD= os.environ.get("ADMIN_PASSWORD", "spann3r$")

SESSION_TTL   = 60 * 60 * 24 * 7   # 7 days in seconds
ADMIN_USER    = "admin"

_file_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Password hashing (no bcrypt dependency — use PBKDF2 from stdlib)
# ---------------------------------------------------------------------------
def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2:{salt}:{h.hex()}"

def _check_password(password: str, stored: str) -> bool:
    try:
        _, salt, hx = stored.split(":")
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
        return secrets.compare_digest(h.hex(), hx)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# File I/O helpers
# ---------------------------------------------------------------------------
def _read_json(path: Path, default) -> dict | list:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def _write_json(path: Path, data) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    shutil.move(str(tmp), str(path))


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
def _load_users() -> dict:
    return _read_json(USERS_FILE, {})

def _save_users(users: dict) -> None:
    _write_json(USERS_FILE, users)

def _ensure_admin():
    users = _load_users()
    if ADMIN_USER not in users:
        users[ADMIN_USER] = {
            "passwordHash": _hash_password(ADMIN_PASSWORD),
            "role": "admin",
            "datasets": "*",          # admin sees all datasets
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
        _save_users(users)
        print(f"[onespan] Created admin account. Username: admin  Password: {ADMIN_PASSWORD}")
    else:
        print(f"[onespan] Admin account exists.")


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def _load_sessions() -> dict:
    return _read_json(SESSIONS_FILE, {})

def _save_sessions(sessions: dict) -> None:
    _write_json(SESSIONS_FILE, sessions)

def _create_session(username: str, role: str) -> str:
    token = secrets.token_hex(32)
    sessions = _load_sessions()
    # Remove old sessions for this user
    sessions = {k: v for k, v in sessions.items() if v.get("username") != username}
    sessions[token] = {
        "username": username,
        "role": role,
        "createdAt": time.time(),
    }
    _save_sessions(sessions)
    return token

def _get_session(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    sessions = _load_sessions()
    session = sessions.get(token)
    if not session:
        return None
    if time.time() - session["createdAt"] > SESSION_TTL:
        del sessions[token]
        _save_sessions(sessions)
        return None
    return session

def _delete_session(token: str) -> None:
    sessions = _load_sessions()
    sessions.pop(token, None)
    _save_sessions(sessions)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
_DEMO_SESSION = {"username": "demo", "role": "admin"}

def _require_session(request: Request) -> dict:
    if DEMO_MODE and request.cookies.get("onespan_session") == DEMO_TOKEN:
        return _DEMO_SESSION
    token = request.cookies.get("onespan_session")
    session = _get_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="Not logged in")
    return session

def _require_admin(request: Request) -> dict:
    session = _require_session(request)
    if session.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return session

def _user_can_access_dataset(username: str, dataset_id: str) -> bool:
    users = _load_users()
    user = users.get(username)
    if not user:
        return False
    access = user.get("datasets", [])
    if access == "*":
        return True
    return dataset_id in access


# ---------------------------------------------------------------------------
# Annotation data
# ---------------------------------------------------------------------------
def _read_data() -> dict:
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cannot read data file: {e}")

async def _write_data(body: dict) -> None:
    async with _file_lock:
        try:
            _write_json(DATA_FILE, body)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Cannot write data file: {e}")

async def _parse_body(request: Request) -> dict:
    raw = await request.body()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty request body")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    for path, default in [
        (DATA_FILE,     {"datasets": [], "activeDatasetId": None}),
        (USERS_FILE,    {}),
        (SESSIONS_FILE, {}),
        (TRACKING_FILE, {"records": []}),
        (SETTINGS_FILE, {"idleThresholdMinutes": 4}),
    ]:
        if not path.exists():
            _write_json(path, default)
    if DEMO_MODE:
        if not DEMO_DATA_FILE.exists():
            _write_json(DEMO_DATA_FILE, {"datasets": [], "activeDatasetId": None})
        print(f"[onespan] *** DEMO MODE ENABLED ***")
        print(f"[onespan] Demo data: {DEMO_DATA_FILE.resolve()}")
    _ensure_admin()
    print(f"[onespan] Listening: http://0.0.0.0:{PORT}/")
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="OneSpan", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
@app.get("", response_class=HTMLResponse)
async def serve_ui(response: Response):
    if not HTML_FILE.exists():
        raise HTTPException(status_code=404, detail=f"index.html not found at {HTML_FILE.resolve()}")
    html = HTML_FILE.read_text(encoding="utf-8")
    if DEMO_MODE:
        html = html.replace("</head>",
            '  <meta name="onespan-demo" content="true">\n</head>', 1)
        response.set_cookie(
            key="onespan_session", value=DEMO_TOKEN,
            httponly=True, samesite="lax", max_age=60*60*24)
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.post("/auth/login")
async def login(request: Request, response: Response):
    body = await _parse_body(request)
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    users = _load_users()
    user = users.get(username)
    if not user or not _check_password(password, user["passwordHash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = _create_session(username, user["role"])
    response.set_cookie(
        key="onespan_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL,
    )
    return {
        "ok": True,
        "username": username,
        "role": user["role"],
        "annotatorId": user.get("annotatorId", username),
    }


@app.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("onespan_session")
    if token:
        _delete_session(token)
    response.delete_cookie("onespan_session")
    return {"ok": True}


@app.get("/auth/me")
async def me(request: Request):
    if DEMO_MODE and request.cookies.get("onespan_session") == DEMO_TOKEN:
        return {"username": "demo", "role": "admin",
                "annotatorId": "demo", "datasets": "*", "demoMode": True}
    session = _require_session(request)
    users = _load_users()
    user = users.get(session["username"], {})
    return {
        "username": session["username"],
        "role": session["role"],
        "annotatorId": user.get("annotatorId", session["username"]),
        "datasets": user.get("datasets", []),
    }


@app.post("/auth/change-password")
async def change_password(request: Request):
    session = _require_session(request)
    body = await _parse_body(request)
    current  = body.get("current", "")
    new_pass = body.get("new", "")

    if len(new_pass) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    users = _load_users()
    user = users.get(session["username"])
    if not user or not _check_password(current, user["passwordHash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    users[session["username"]]["passwordHash"] = _hash_password(new_pass)
    _save_users(users)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------
@app.get("/admin/users")
async def admin_list_users(request: Request):
    _require_admin(request)
    users = _load_users()
    return [
        {
            "username": k,
            "role": v.get("role", "annotator"),
            "annotatorId": v.get("annotatorId", k),
            "datasets": v.get("datasets", []),
            "createdAt": v.get("createdAt", ""),
        }
        for k, v in users.items()
    ]


@app.post("/admin/users")
async def admin_create_user(request: Request):
    _require_admin(request)
    body = await _parse_body(request)
    username    = body.get("username", "").strip().lower()
    password    = body.get("password", "")
    annotator_id= body.get("annotatorId", "").strip() or username
    datasets    = body.get("datasets", [])

    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    users = _load_users()
    if username in users:
        raise HTTPException(status_code=409, detail=f"User '{username}' already exists")

    users[username] = {
        "passwordHash": _hash_password(password),
        "role": "annotator",
        "annotatorId": annotator_id,
        "datasets": datasets,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    _save_users(users)
    return {"ok": True, "username": username}


@app.delete("/admin/users/{username}")
async def admin_delete_user(username: str, request: Request):
    _require_admin(request)
    if username == ADMIN_USER:
        raise HTTPException(status_code=400, detail="Cannot delete the admin account")
    users = _load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    del users[username]
    _save_users(users)
    return {"ok": True}


@app.post("/admin/users/{username}/reset-password")
async def admin_reset_password(username: str, request: Request):
    _require_admin(request)
    body = await _parse_body(request)
    new_pass = body.get("password", "")
    if len(new_pass) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    users = _load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[username]["passwordHash"] = _hash_password(new_pass)
    _save_users(users)
    return {"ok": True}


@app.post("/admin/users/{username}/datasets")
async def admin_set_datasets(username: str, request: Request):
    _require_admin(request)
    body = await _parse_body(request)
    datasets = body.get("datasets", [])   # list of dataset IDs, or "*"
    users = _load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[username]["datasets"] = datasets
    _save_users(users)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Data routes — filtered by user access
# ---------------------------------------------------------------------------
@app.get("/data")
@app.get("/data/")
async def get_data(request: Request):
    session = _require_session(request)
    if DEMO_MODE and session["username"] == "demo":
        try:
            data = json.loads(DEMO_DATA_FILE.read_text(encoding="utf-8"))
        except Exception:
            data = {"datasets": [], "activeDatasetId": None}
        return JSONResponse(content=data)
    data = _read_data()
    if session["role"] != "admin":
        data["datasets"] = [
            d for d in data.get("datasets", [])
            if _user_can_access_dataset(session["username"], d["id"])
        ]
    return JSONResponse(content=data)


@app.post("/data")
@app.post("/data/")
async def save_data(request: Request):
    session = _require_session(request)
    body = await _parse_body(request)

    if not isinstance(body, dict) or "datasets" not in body:
        raise HTTPException(status_code=400, detail='Body must contain "datasets" key')

    # For non-admins: only allow saving datasets they have access to
    # Merge their changes into the full dataset (preserve datasets they can't see)
    if session["role"] != "admin":
        full_data = _read_data()
        their_ids = {d["id"] for d in body.get("datasets", [])}
        # Keep datasets the user can't access untouched
        others = [
            d for d in full_data.get("datasets", [])
            if not _user_can_access_dataset(session["username"], d["id"])
        ]
        # Validate they're only writing to datasets they have access to
        for ds in body.get("datasets", []):
            if not _user_can_access_dataset(session["username"], ds["id"]):
                raise HTTPException(status_code=403, detail=f"No access to dataset {ds['id']}")
        body["datasets"] = body["datasets"] + others

    # Demo: write to demo_dataset.json only
    if DEMO_MODE and session["username"] == "demo":
        body.setdefault("activeDatasetId", None)
        async with _file_lock:
            _write_json(DEMO_DATA_FILE, body)
        return JSONResponse({"ok": True, "demo": True,
            "savedAt": datetime.now(timezone.utc).isoformat(),
            "datasetCount": len(body.get("datasets", []))})

    body.setdefault("activeDatasetId", None)
    await _write_data(body)

    return JSONResponse({
        "ok": True,
        "savedAt": datetime.now(timezone.utc).isoformat(),
        "datasetCount": len(body.get("datasets", [])),
    })


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Time tracking
# ---------------------------------------------------------------------------
@app.post("/tracking")
@app.post("/tracking/")
async def post_tracking(request: Request):
    """Record a heartbeat of active annotation time."""
    session = _require_session(request)
    body = await _parse_body(request)

    annotator = session["username"]
    users = _load_users()
    annotator_id = users.get(annotator, {}).get("annotatorId", annotator)

    dataset_id = body.get("datasetId")
    date       = body.get("date")
    add_sec    = int(body.get("activeSeconds", 0))
    add_evt    = int(body.get("events", 0))
    add_spans  = int(body.get("spansCreated", 0))

    if not dataset_id or not date:
        raise HTTPException(status_code=400, detail="datasetId and date required")

    async with _file_lock:
        tracking = _read_json(TRACKING_FILE, {"records": []})
        records = tracking.get("records", [])
        match = None
        for r in records:
            if (r["annotatorId"] == annotator_id and
                r["datasetId"] == dataset_id and
                r["date"] == date):
                match = r
                break
        if match:
            match["activeSeconds"] += add_sec
            match["events"]        += add_evt
            match["spansCreated"]  += add_spans
        else:
            records.append({
                "annotatorId":   annotator_id,
                "datasetId":     dataset_id,
                "date":          date,
                "activeSeconds": add_sec,
                "events":        add_evt,
                "spansCreated":  add_spans,
            })
        tracking["records"] = records
        _write_json(TRACKING_FILE, tracking)

    return {"ok": True}


@app.get("/tracking")
@app.get("/tracking/")
async def get_tracking(request: Request):
    """Admin-only: return all time-tracking records."""
    _require_admin(request)
    return _read_json(TRACKING_FILE, {"records": []})


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
@app.get("/settings")
@app.get("/settings/")
async def get_settings(request: Request):
    """Any logged-in user can read settings (needed for idle threshold)."""
    _require_session(request)
    return _read_json(SETTINGS_FILE, {"idleThresholdMinutes": 4})


@app.post("/settings")
@app.post("/settings/")
async def post_settings(request: Request):
    """Admin-only: update settings."""
    _require_admin(request)
    body = await _parse_body(request)
    settings = _read_json(SETTINGS_FILE, {"idleThresholdMinutes": 4})
    if "idleThresholdMinutes" in body:
        try:
            v = float(body["idleThresholdMinutes"])
            if v < 0.5 or v > 60:
                raise ValueError()
            settings["idleThresholdMinutes"] = v
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="idleThresholdMinutes must be 0.5-60")
    async with _file_lock:
        _write_json(SETTINGS_FILE, settings)
    return {"ok": True, "settings": settings}


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "dataFile": str(DATA_FILE.resolve()),
        "dataFileExists": DATA_FILE.exists(),
        "usersFile": str(USERS_FILE.resolve()),
        "htmlFile": str(HTML_FILE.resolve()),
    }


if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=PORT,
        reload=False,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
