import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import shutil
import sqlite3
import tempfile
import time
import urllib.parse
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, Request, Form, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_DIR = Path(os.environ.get("DB_DIR", str(BASE_DIR)))
DB_PATH = DB_DIR / "patrol.db"

APP_VERSION = "4.2 (волна 3: штаб)"
START_TIME = datetime.now()

SECRET_KEY = os.environ.get("SECRET_KEY", "zameni-menya-na-sluchaynuyu-stroku")
PATROL_PIN = os.environ.get("PATROL_PIN", "1234")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "1029384756")
DEV_PASSWORD = os.environ.get("DEV_PASSWORD", "developer")
ADMIN_LABEL = "АДМИНИСТРАТОР"

STATUS_LABELS = {
    "new": "Новое",
    "talk": "Проведена беседа",
    "closed": "Закрыто",
}

TRASH_DAYS = 30

DEFAULT_PATROL_NAMES = [
    "Борисов",
    "Соколов",
    "Ипполитов",
    "Старовойтов",
    "Алешин",
    "Иванов",
    "Нилов",
    "Дрейден",
    "Лунев",
    "Халин",
    "Позднякова",
    "Глущенко",
    "Малькин",
    "Макарова",
    "Соболев",
    "Сахно",
    "Сорокин",
    "Барболина",
    "Зиновьева",
    "Метлёнкина",
    "Павловская",
    "Григорьева",
]

VIOLATION_TYPES = [
    "Опоздание",
    "Нарушение лок. акта №36",
    "Нарушение дисциплины",
    "Курение в неположенном месте",
    "Другое",
]

VIOLATION_COLORS = {
    "Опоздание": "orange",
    "Нарушение лок. акта №36": "yellow",
    "Нарушение дисциплины": "red",
    "Курение в неположенном месте": "darkred",
    "Другое": "gray",
}

DEPARTMENTS = {
    "ЗЧС": "Отделение ЗЧС",
    "ПБ": "Отделение ПБ",
    "БПЛА": "Отделение БПЛА",
    "МК": "Отделение МК",
    "СР": "Отделение СР",
    "ЮП": "Отделение ЮП",
    "ЭБПК": "Отделение ЭБПК",
}

COOKIE_PATROL_NAME = "patrol_name"
COOKIE_AUTH_ROLE = "auth_role"
COOKIE_MAX_AGE_30_DAYS = 60 * 60 * 24 * 30

PER_PAGE = 50
SORTABLE_COLUMNS = ["id", "created_at", "patrol_name", "student_name", "student_group", "violation_type"]

app = FastAPI(title="Патрульная служба колледжа")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ---------------------------------------------------------------------------
# Защитные заголовки и запрет кеша статики
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

@app.middleware("http")
async def no_cache_static(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response

# ---------------------------------------------------------------------------
# База данных и миграции
# ---------------------------------------------------------------------------
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patrol_name TEXT NOT NULL,
            student_name TEXT NOT NULL,
            student_group TEXT NOT NULL,
            violation_type TEXT NOT NULL,
            comment TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS patrol_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS duty_schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            duty_date TEXT NOT NULL,
            patrol_name TEXT NOT NULL,
            UNIQUE(duty_date, patrol_name)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shifts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patrol_name TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            duration_minutes INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS error_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            path TEXT,
            message TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            actor TEXT,
            role TEXT,
            action TEXT,
            details TEXT
        )
        """
    )
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(violations)").fetchall()]
    if "status" not in cols:
        conn.execute("ALTER TABLE violations ADD COLUMN status TEXT DEFAULT 'new'")
    if "deleted_at" not in cols:
        conn.execute("ALTER TABLE violations ADD COLUMN deleted_at TEXT")
    conn.execute("UPDATE violations SET status = 'new' WHERE status IS NULL OR status = ''")
    conn.execute(
        "UPDATE violations SET violation_type = ? WHERE violation_type = ?",
        ("Нарушение лок. акта №36", "Отсутствие формы / бейджа"),
    )
    count = conn.execute("SELECT COUNT(*) FROM patrol_members").fetchone()[0]
    if count == 0:
        for name in DEFAULT_PATROL_NAMES:
            conn.execute("INSERT INTO patrol_members (name) VALUES (?)", (name,))
    conn.commit()
    conn.close()

@app.on_event("startup")
def on_startup() -> None:
    init_db()

# ---------------------------------------------------------------------------
# PWA
# ---------------------------------------------------------------------------
@app.get("/sw.js")
async def service_worker():
    return FileResponse(BASE_DIR / "static" / "sw.js", media_type="application/javascript")

@app.get("/manifest.webmanifest")
async def manifest():
    return FileResponse(BASE_DIR / "static" / "manifest.webmanifest", media_type="application/manifest+json")

# ---------------------------------------------------------------------------
# Журналы: ошибок и аудита
# ---------------------------------------------------------------------------
def log_error(path: str, message: str) -> None:
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO error_log (created_at, path, message) VALUES (?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), path, message[:2000]),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def log_action(request: Request, action: str, details: str = "") -> None:
    try:
        role = get_role(request)
        patrol = get_patrol_name(request)
        if role == "dev":
            actor, role_name = "разработчик", "dev"
        elif role == "admin":
            actor, role_name = "админ", "admin"
        elif patrol:
            actor, role_name = patrol, "patrol"
        else:
            actor, role_name = "аноним", "anon"
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO audit_log (created_at, actor, role, action, details) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), actor, role_name, action, details[:500]),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code >= 500:
        log_error(request.url.path, f"HTTP {exc.status_code}: {exc.detail}")
    message = "Страница не найдена." if exc.status_code == 404 else str(exc.detail)
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "code": exc.status_code, "message": message},
        status_code=exc.status_code,
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log_error(request.url.path, f"{type(exc).__name__}: {exc}")
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "code": 500, "message": "Внутренняя ошибка сервера. Попробуйте обновить страницу позже."},
        status_code=500,
    )

# ---------------------------------------------------------------------------
# Защита: подписи cookie, соль сессий, лимит попыток
# ---------------------------------------------------------------------------
def _sign_key() -> bytes:
    return (SECRET_KEY + "|" + get_meta("session_salt", "")).encode()

def sign_value(value: str) -> str:
    sig = hmac.new(_sign_key(), value.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{value}.{sig}"

def verify_signed(raw: Optional[str]) -> Optional[str]:
    if not raw or "." not in raw:
        return None
    value, sig = raw.rsplit(".", 1)
    expected = hmac.new(_sign_key(), value.encode(), hashlib.sha256).hexdigest()[:32]
    if hmac.compare_digest(sig, expected):
        return value
    return None

LOGIN_ATTEMPTS: dict = {}
RATE_LIMIT_WINDOW = 600
RATE_LIMIT_MAX = 5

def get_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def rate_limited(ip: str) -> bool:
    now = time.time()
    hits = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
    LOGIN_ATTEMPTS[ip] = hits
    return len(hits) >= RATE_LIMIT_MAX

def register_fail(ip: str) -> None:
    LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())

def clear_fails(ip: str) -> None:
    LOGIN_ATTEMPTS.pop(ip, None)

# ---------------------------------------------------------------------------
# Настройки (meta) и справочники
# ---------------------------------------------------------------------------
def get_meta(key: str, default: str = "") -> str:
    conn = get_db_connection()
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row and row["value"] is not None else default

def set_meta(key: str, value: str) -> None:
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()

def get_pin() -> str:
    return get_meta("patrol_pin") or PATROL_PIN

def get_admin_password() -> str:
    return get_meta("admin_password") or ADMIN_PASSWORD

def get_dev_password() -> str:
    return get_meta("dev_password") or DEV_PASSWORD

def get_deviant_min() -> int:
    try:
        return max(1, int(get_meta("deviant_min", "2")))
    except ValueError:
        return 2

def get_deviants_reset_at() -> str:
    return get_meta("deviants_reset_at", "")

def get_violation_types():
    raw = get_meta("violation_types")
    if raw:
        try:
            lst = json.loads(raw)
            if isinstance(lst, list) and lst:
                return lst
        except ValueError:
            pass
    return list(VIOLATION_TYPES)

def get_departments():
    raw = get_meta("departments")
    if raw:
        try:
            d = json.loads(raw)
            if isinstance(d, dict) and d:
                return d
        except ValueError:
            pass
    return dict(DEPARTMENTS)

# ---------------------------------------------------------------------------
# Роли и вспомогательные функции
# ---------------------------------------------------------------------------
def get_role(request: Request) -> Optional[str]:
    return verify_signed(request.cookies.get(COOKIE_AUTH_ROLE))

def is_admin(request: Request) -> bool:
    return get_role(request) in ("admin", "dev")

def is_dev(request: Request) -> bool:
    return get_role(request) == "dev"

templates.env.globals["is_dev"] = is_dev

def get_patrol_names():
    conn = get_db_connection()
    rows = conn.execute("SELECT name FROM patrol_members ORDER BY id").fetchall()
    conn.close()
    return [r["name"] for r in rows]

def get_patrol_name(request: Request) -> Optional[str]:
    verified = verify_signed(request.cookies.get(COOKIE_PATROL_NAME))
    if not verified:
        return None
    name = urllib.parse.unquote(verified)
    if name in get_patrol_names():
        return name
    return None

def get_badge_class(violation_type: str) -> str:
    return f"badge badge-{VIOLATION_COLORS.get(violation_type, 'gray')}"

def get_status_class(status: str) -> str:
    return {"new": "badge badge-red", "talk": "badge badge-orange", "closed": "badge badge-green"}.get(status, "badge badge-gray")

def get_repeat_offenders(min_count: Optional[int] = None):
    if min_count is None:
        min_count = get_deviant_min()
    reset = get_deviants_reset_at()
    query = "SELECT student_name FROM violations WHERE deleted_at IS NULL"
    params: list = []
    if reset:
        query += " AND created_at >= ?"
        params.append(reset + " 00:00:00")
    query += " GROUP BY student_name HAVING COUNT(*) >= ?"
    params.append(min_count)
    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [r["student_name"] for r in rows]

def get_known_students():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT student_name, student_group FROM violations WHERE deleted_at IS NULL ORDER BY id DESC"
    ).fetchall()
    conn.close()
    known = {}
    for row in rows:
        known.setdefault(row["student_name"], row["student_group"])
    return known

def build_violations_query(student_name, group, violation_type, date_from, date_to, q=None, has_comment=False, status=None, include_deleted=False):
    query = "SELECT * FROM violations WHERE 1=1"
    params = []
    if not include_deleted:
        query += " AND deleted_at IS NULL"
    if student_name:
        query += " AND student_name LIKE ?"
        params.append(f"%{student_name}%")
    if group:
        query += " AND student_group LIKE ?"
        params.append(f"%{group}%")
    if violation_type:
        query += " AND violation_type = ?"
        params.append(violation_type)
    if date_from:
        query += " AND created_at >= ?"
        params.append(f"{date_from} 00:00:00")
    if date_to:
        query += " AND created_at <= ?"
        params.append(f"{date_to} 23:59:59")
    if q:
        like = f"%{q}%"
        query += " AND (student_name LIKE ? OR patrol_name LIKE ? OR student_group LIKE ? OR comment LIKE ?)"
        params += [like, like, like, like]
    if has_comment:
        query += " AND comment IS NOT NULL AND comment != ''"
    if status:
        query += " AND status = ?"
        params.append(status)
    return query, params

def toast_redirect(url: str, message: str) -> RedirectResponse:
    return RedirectResponse(url + "?toast=" + urllib.parse.quote(message), status_code=303)

def format_duration(minutes: int) -> str:
    h = minutes // 60
    m = minutes % 60
    if h:
        return f"{h} ч {m} мин"
    return f"{m} мин"

def human_size(n: float) -> str:
    for unit in ["Б", "КБ", "МБ", "ГБ"]:
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"

def render_csv(rows) -> str:
    buffer = io.StringIO()
    buffer.write("\ufeff")
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow(
        ["ID", "Патрульный", "ФИО студента", "Группа", "Тип нарушения", "Комментарий", "Дата и время", "Статус"]
    )
    for row in rows:
        writer.writerow(
            [
                row["id"],
                row["patrol_name"],
                row["student_name"],
                row["student_group"],
                row["violation_type"],
                row["comment"] or "",
                row["created_at"],
                STATUS_LABELS.get(row["status"] or "new", row["status"] or "new"),
            ]
        )
    return buffer.getvalue()

# ---------------------------------------------------------------------------
# Маршруты патрульного
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def patrol_home(request: Request):
    patrol_name = get_patrol_name(request)
    if not patrol_name:
        return templates.TemplateResponse(
            "patrol.html",
            {"request": request, "logged_in": False, "patrol_names": get_patrol_names(), "error": None},
        )
    known = get_known_students()
    today = datetime.now().strftime("%Y-%m-%d")
    month_ago = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    conn = get_db_connection()
    duty_rows = conn.execute("SELECT patrol_name FROM duty_schedule WHERE duty_date = ?", (today,)).fetchall()
    open_shift = conn.execute(
        "SELECT started_at FROM shifts WHERE patrol_name = ? AND ended_at IS NULL", (patrol_name,)
    ).fetchone()
    my_shifts = conn.execute(
        "SELECT duration_minutes FROM shifts WHERE patrol_name = ? AND ended_at IS NOT NULL AND started_at >= ?",
        (patrol_name, month_ago + " 00:00:00"),
    ).fetchall()
    conn.close()
    duty_names = [r["patrol_name"] for r in duty_rows]
    return templates.TemplateResponse(
        "patrol.html",
        {
            "request": request,
            "logged_in": True,
            "patrol_name": patrol_name,
            "violation_types": get_violation_types(),
            "known_students": sorted(known.keys()),
            "student_groups_json": json.dumps(known, ensure_ascii=False),
            "on_duty_today": patrol_name in duty_names,
            "duty_colleagues": [n for n in duty_names if n != patrol_name],
            "open_shift": open_shift["started_at"] if open_shift else None,
            "my_shifts_count": len(my_shifts),
            "my_hours": round(sum(r["duration_minutes"] or 0 for r in my_shifts) / 60, 1),
        },
    )

@app.post("/patrol/login")
def patrol_login(
    request: Request,
    patrol_name: str = Form(...),
    pin: str = Form(...),
):
    ip = get_client_ip(request)
    names = get_patrol_names()
    if rate_limited(ip):
        return templates.TemplateResponse(
            "patrol.html",
            {
                "request": request,
                "logged_in": False,
                "patrol_names": names,
                "error": "Слишком много попыток входа. Повторите через 10 минут.",
            },
            status_code=429,
        )
    if patrol_name not in names or pin != get_pin():
        register_fail(ip)
        log_action(request, "вход патрульного: отказ", patrol_name)
        return templates.TemplateResponse(
            "patrol.html",
            {
                "request": request,
                "logged_in": False,
                "patrol_names": names,
                "error": "Неверное ФИО или ПИН-код. Попробуйте ещё раз.",
            },
            status_code=400,
        )
    clear_fails(ip)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key=COOKIE_PATROL_NAME,
        value=sign_value(urllib.parse.quote(patrol_name)),
        max_age=COOKIE_MAX_AGE_30_DAYS,
        httponly=True,
        samesite="lax",
        secure=True,
    )
    log_action(request, "вход патрульного", patrol_name)
    return response

@app.get("/patrol/logout")
def patrol_logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(COOKIE_PATROL_NAME)
    return response

@app.post("/shift/start")
def shift_start(request: Request):
    patrol_name = get_patrol_name(request)
    if not patrol_name:
        return RedirectResponse(url="/", status_code=303)
    conn = get_db_connection()
    open_row = conn.execute(
        "SELECT id FROM shifts WHERE patrol_name = ? AND ended_at IS NULL", (patrol_name,)
    ).fetchone()
    if open_row:
        conn.close()
        return toast_redirect("/", "Смена уже начата")
    conn.execute(
        "INSERT INTO shifts (patrol_name, started_at) VALUES (?, ?)",
        (patrol_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()
    log_action(request, "смена начата", patrol_name)
    return toast_redirect("/", "Смена начата ✓")

@app.post("/shift/end")
def shift_end(request: Request):
    patrol_name = get_patrol_name(request)
    if not patrol_name:
        return RedirectResponse(url="/", status_code=303)
    conn = get_db_connection()
    open_row = conn.execute(
        "SELECT * FROM shifts WHERE patrol_name = ? AND ended_at IS NULL", (patrol_name,)
    ).fetchone()
    if not open_row:
        conn.close()
        return toast_redirect("/", "Нет активной смены")
    now = datetime.now()
    started = datetime.strptime(open_row["started_at"], "%Y-%m-%d %H:%M:%S")
    minutes = int((now - started).total_seconds() // 60)
    conn.execute(
        "UPDATE shifts SET ended_at = ?, duration_minutes = ? WHERE id = ?",
        (now.strftime("%Y-%m-%d %H:%M:%S"), minutes, open_row["id"]),
    )
    conn.commit()
    conn.close()
    log_action(request, "смена завершена", f"{patrol_name}, {format_duration(minutes)}")
    return toast_redirect("/", f"Смена завершена: {format_duration(minutes)}")

@app.post("/add")
def add_violation(
    request: Request,
    student_group: str = Form(...),
    student_name: str = Form(...),
    violation_type: str = Form(...),
    comment: str = Form(""),
    dup_confirm: str = Form("0"),
):
    patrol_name = get_patrol_name(request)
    if not patrol_name:
        return RedirectResponse(url="/", status_code=303)

    student_name_clean = student_name.strip()
    today = datetime.now().strftime("%Y-%m-%d")

    conn = get_db_connection()
    dup = conn.execute(
        "SELECT id FROM violations WHERE deleted_at IS NULL AND lower(student_name) = lower(?) AND violation_type = ? AND created_at >= ?",
        (student_name_clean, violation_type, today + " 00:00:00"),
    ).fetchone()

    if dup and dup_confirm != "1":
        known = get_known_students()
        conn.close()
        return templates.TemplateResponse(
            "patrol.html",
            {
                "request": request,
                "logged_in": True,
                "patrol_name": patrol_name,
                "violation_types": get_violation_types(),
                "known_students": sorted(known.keys()),
                "student_groups_json": json.dumps(known, ensure_ascii=False),
                "dup_warning": f"Сегодня уже записано нарушение «{violation_type}» для студента {student_name_clean}. Сохранить ещё раз?",
                "form_group": student_group.strip(),
                "form_name": student_name_clean,
                "form_type": violation_type,
                "form_comment": comment.strip(),
                "on_duty_today": False,
                "duty_colleagues": [],
                "open_shift": None,
                "my_shifts_count": 0,
                "my_hours": 0,
            },
        )

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """
        INSERT INTO violations
            (patrol_name, student_name, student_group, violation_type, comment, created_at, status)
        VALUES (?, ?, ?, ?, ?, ?, 'new')
        """,
        (patrol_name, student_name_clean, student_group.strip(), violation_type, comment.strip(), created_at),
    )
    conn.commit()
    conn.close()
    log_action(request, "добавлено нарушение", f"{student_name_clean}, {student_group.strip()}, {violation_type}")
    return toast_redirect("/", "Нарушение сохранено ✓")

# ---------------------------------------------------------------------------
# Служебные проверки
# ---------------------------------------------------------------------------
@app.get("/check/student")
def check_student(request: Request, name: str = ""):
    if not get_patrol_name(request) and not is_admin(request):
        return HTMLResponse(
            content=json.dumps({"ok": False}),
            media_type="application/json",
            status_code=403,
        )
    q = name.strip()
    matches = []
    if len(q) >= 3:
        today = datetime.now().strftime("%Y-%m-%d")
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT student_name, COUNT(*) AS c, MAX(created_at) AS last "
            "FROM violations WHERE deleted_at IS NULL GROUP BY student_name"
        ).fetchall()
        today_rows = conn.execute(
            "SELECT student_name, violation_type FROM violations WHERE deleted_at IS NULL AND created_at >= ?",
            (today + " 00:00:00",),
        ).fetchall()
        conn.close()
        today_types = {}
        for t in today_rows:
            today_types.setdefault(t["student_name"].casefold(), set()).add(t["violation_type"])
        ql = q.casefold()
        for r in rows:
            if r["student_name"].casefold().startswith(ql):
                matches.append(
                    {
                        "name": r["student_name"],
                        "count": r["c"],
                        "last": r["last"][:10],
                        "today_types": sorted(today_types.get(r["student_name"].casefold(), set())),
                    }
                )
        matches.sort(key=lambda m: m["count"], reverse=True)
        matches = matches[:5]
    return HTMLResponse(
        content=json.dumps({"ok": True, "matches": matches}, ensure_ascii=False),
        media_type="application/json",
    )

@app.get("/check/dossier")
def check_dossier(request: Request, name: str = ""):
    if not get_patrol_name(request) and not is_admin(request):
        return HTMLResponse(
            content=json.dumps({"ok": False}),
            media_type="application/json",
            status_code=403,
        )
    q = name.strip().casefold()
    items = []
    if q:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM violations WHERE deleted_at IS NULL ORDER BY created_at DESC").fetchall()
        conn.close()
        items = [
            {
                "created_at": r["created_at"],
                "violation_type": r["violation_type"],
                "student_group": r["student_group"],
                "patrol_name": r["patrol_name"],
                "comment": r["comment"] or "",
            }
            for r in rows
            if r["student_name"].casefold() == q
        ]
    return HTMLResponse(
        content=json.dumps({"ok": True, "items": items}, ensure_ascii=False),
        media_type="application/json",
    )

# ---------------------------------------------------------------------------
# Вход администратора и разработчика
# ---------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def admin_login_form(request: Request):
    if is_admin(request):
        return RedirectResponse(url="/admin", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None},
    )

@app.post("/login")
def admin_login(request: Request, password: str = Form(...)):
    ip = get_client_ip(request)
    if rate_limited(ip):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Слишком много попыток входа. Повторите через 10 минут."},
            status_code=429,
        )
    if password == get_dev_password():
        role = "dev"
    elif password == get_admin_password():
        role = "admin"
    else:
        register_fail(ip)
        log_action(request, "вход в админку: отказ", f"IP {ip}")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный пароль. Попробуйте ещё раз."},
            status_code=400,
        )
    clear_fails(ip)
    log_action(request, "вход в админку", f"роль {role}, IP {ip}")
    response = RedirectResponse(url="/admin", status_code=303)
    response.set_cookie(
        key=COOKIE_AUTH_ROLE,
        value=sign_value(role),
        httponly=True,
        samesite="lax",
        secure=True,
    )
    return response

@app.get("/admin/logout")
def admin_logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(COOKIE_AUTH_ROLE)
    return response

# ---------------------------------------------------------------------------
# Служебный контур разработчика
# ---------------------------------------------------------------------------
@app.get("/dev/system", response_class=HTMLResponse)
def dev_system(request: Request):
    if not is_dev(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    counts = {
        "violations": conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NULL").fetchone()[0],
        "patrol_members": conn.execute("SELECT COUNT(*) FROM patrol_members").fetchone()[0],
        "duty_schedule": conn.execute("SELECT COUNT(*) FROM duty_schedule").fetchone()[0],
        "shifts": conn.execute("SELECT COUNT(*) FROM shifts").fetchone()[0],
        "error_log": conn.execute("SELECT COUNT(*) FROM error_log").fetchone()[0],
        "trash": conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NOT NULL").fetchone()[0],
        "audit": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
    }
    conn.close()

    uptime = datetime.now() - START_TIME
    uptime_str = f"{uptime.days} дн. {uptime.seconds // 3600} ч. {(uptime.seconds % 3600) // 60} мин."

    try:
        db_size = human_size(os.path.getsize(DB_PATH))
    except OSError:
        db_size = "недоступно"

    warnings = []
    if SECRET_KEY == "zameni-menya-na-sluchaynuyu-stroku":
        warnings.append("SECRET_KEY не задан в переменных окружения: используется значение по умолчанию.")
    if get_dev_password() == DEV_PASSWORD and DEV_PASSWORD == "developer":
        warnings.append("Пароль разработчика не изменён: задайте переменную DEV_PASSWORD или смените его в meta.")
    if not get_meta("session_salt"):
        warnings.append("Соль сессий не инициализирована: выполните сброс сессий на странице «Резерв и сессии».")

    return templates.TemplateResponse(
        "dev_system.html",
        {
            "request": request,
            "version": APP_VERSION,
            "uptime": uptime_str,
            "counts": counts,
            "db_size": db_size,
            "db_dir": str(DB_DIR),
            "db_writable": os.access(DB_DIR, os.W_OK),
            "last_export": get_meta("last_export_at", "") or "никогда",
            "last_db_backup": get_meta("last_db_backup_at", "") or "никогда",
            "types_count": len(get_violation_types()),
            "deps_count": len(get_departments()),
            "deviant_min": get_deviant_min(),
            "deviants_reset_at": get_deviants_reset_at() or "не сбрасывался",
            "warnings": warnings,
        },
    )

@app.get("/dev/errors", response_class=HTMLResponse)
def dev_errors(request: Request):
    if not is_dev(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM error_log ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return templates.TemplateResponse(
        "dev_errors.html",
        {"request": request, "rows": rows},
    )

@app.post("/dev/errors/clear")
def dev_errors_clear(request: Request):
    if not is_dev(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute("DELETE FROM error_log")
    conn.commit()
    conn.close()
    log_action(request, "журнал ошибок очищен")
    return toast_redirect("/dev/errors", "Журнал ошибок очищен")

@app.get("/dev/tools", response_class=HTMLResponse)
def dev_tools(request: Request):
    if not is_dev(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "dev_tools.html",
        {
            "request": request,
            "last_db_backup": get_meta("last_db_backup_at", "") or "никогда",
        },
    )

@app.get("/dev/backup")
def dev_backup(request: Request):
    if not is_dev(request):
        return RedirectResponse(url="/login", status_code=303)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    src = get_db_connection()
    dst = sqlite3.connect(tmp.name)
    src.backup(dst)
    dst.close()
    src.close()
    set_meta("last_db_backup_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    log_action(request, "полный бэкап базы скачан")
    filename = f"patrol_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    return FileResponse(
        tmp.name,
        filename=filename,
        media_type="application/octet-stream",
        background=BackgroundTask(os.remove, tmp.name),
    )

@app.post("/dev/restore-db")
async def dev_restore_db(request: Request, file: UploadFile = File(...)):
    if not is_dev(request):
        return RedirectResponse(url="/login", status_code=303)
    data = await file.read()
    if not data.startswith(b"SQLite format 3\x00"):
        return toast_redirect("/dev/tools", "Файл не является базой данных SQLite")
    tmp_cur = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp_cur.close()
    src = get_db_connection()
    dst = sqlite3.connect(tmp_cur.name)
    src.backup(dst)
    dst.close()
    src.close()
    try:
        with open(DB_PATH, "wb") as f:
            f.write(data)
        conn = get_db_connection()
        conn.execute("SELECT COUNT(*) FROM violations").fetchone()
        conn.close()
        os.remove(tmp_cur.name)
        log_action(request, "база восстановлена из файла")
        return toast_redirect("/dev/tools", "База данных восстановлена из файла")
    except Exception:
        shutil.copyfile(tmp_cur.name, DB_PATH)
        os.remove(tmp_cur.name)
        log_action(request, "ошибка восстановления базы: возвращена прежняя")
        return toast_redirect("/dev/tools", "Ошибка восстановления: возвращена прежняя база")

@app.post("/dev/reset-sessions")
def dev_reset_sessions(request: Request):
    if not is_dev(request):
        return RedirectResponse(url="/login", status_code=303)
    set_meta("session_salt", secrets.token_hex(16))
    log_action(request, "экстренный сброс всех сессий")
    return RedirectResponse(url="/login", status_code=303)

# ---------------------------------------------------------------------------
# Админ-панель
# ---------------------------------------------------------------------------
@app.get("/admin", response_class=HTMLResponse)
def admin_panel(
    request: Request,
    student_name: Optional[str] = None,
    group: Optional[str] = None,
    violation_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    q: Optional[str] = None,
    has_comment: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    sort: str = "created_at",
    dir: str = "desc",
):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    if sort not in SORTABLE_COLUMNS:
        sort = "created_at"
    if dir not in ("asc", "desc"):
        dir = "desc"
    hc = bool(has_comment)

    query, params = build_violations_query(student_name, group, violation_type, date_from, date_to, q=q, has_comment=hc, status=status)
    conn = get_db_connection()
    total = conn.execute(query.replace("SELECT *", "SELECT COUNT(*)", 1), params).fetchone()[0]
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(max(1, page), pages)
    rows = conn.execute(
        query + f" ORDER BY {sort} {dir.upper()}, id DESC LIMIT ? OFFSET ?",
        params + [PER_PAGE, (page - 1) * PER_PAGE],
    ).fetchall()
    conn.close()

    now_dt = datetime.now()
    today_str = now_dt.strftime("%Y-%m-%d")
    monday_str = (now_dt - timedelta(days=now_dt.weekday())).strftime("%Y-%m-%d")
    week_ago_str = (now_dt - timedelta(days=7)).strftime("%Y-%m-%d")

    conn = get_db_connection()
    kpi_today = conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NULL AND created_at >= ?", (today_str + " 00:00:00",)).fetchone()[0]
    kpi_week = conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NULL AND created_at >= ?", (week_ago_str + " 00:00:00",)).fetchone()[0]
    kpi_unprocessed = conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NULL AND status = 'new'").fetchone()[0]
    open_shifts = conn.execute("SELECT COUNT(*) FROM shifts WHERE ended_at IS NULL").fetchone()[0]
    duty_rows = conn.execute("SELECT patrol_name FROM duty_schedule WHERE duty_date = ?", (today_str,)).fetchall()
    conn.close()

    last_visit = get_meta("last_admin_visit", "")
    if last_visit:
        conn = get_db_connection()
        kpi_new = conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NULL AND created_at > ?", (last_visit,)).fetchone()[0]
        conn.close()
    else:
        kpi_new = 0

    last_export = get_meta("last_export_at", "")
    days_since_export = None
    if last_export:
        try:
            days_since_export = (now_dt - datetime.strptime(last_export, "%Y-%m-%d %H:%M:%S")).days
        except ValueError:
            days_since_export = None

    kpi = {
        "today": kpi_today,
        "week": kpi_week,
        "unprocessed": kpi_unprocessed,
        "deviants": len(get_repeat_offenders()),
        "on_duty": [r["patrol_name"] for r in duty_rows],
        "open_shifts": open_shifts,
        "new_since_visit": kpi_new,
        "days_since_export": days_since_export,
    }
    set_meta("last_admin_visit", now_dt.strftime("%Y-%m-%d %H:%M:%S"))

    base_params = {
        "student_name": student_name or "",
        "group": group or "",
        "violation_type": violation_type or "",
        "date_from": date_from or "",
        "date_to": date_to or "",
        "q": q or "",
        "has_comment": "1" if hc else "",
        "status": status or "",
    }
    sort_urls = {}
    for col in SORTABLE_COLUMNS:
        p = dict(base_params)
        p["sort"] = col
        p["dir"] = "asc" if (sort == col and dir == "desc") else "desc"
        sort_urls[col] = "/admin?" + urllib.parse.urlencode({k: v for k, v in p.items() if v})

    page_params = dict(base_params)
    page_params["sort"] = sort
    page_params["dir"] = dir
    prev_url = None
    next_url = None
    if page > 1:
        pp = dict(page_params)
        pp["page"] = page - 1
        prev_url = "/admin?" + urllib.parse.urlencode({k: v for k, v in pp.items() if v})
    if page < pages:
        np = dict(page_params)
        np["page"] = page + 1
        next_url = "/admin?" + urllib.parse.urlencode({k: v for k, v in np.items() if v})

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "violations": rows,
            "violation_types": get_violation_types(),
            "status_labels": STATUS_LABELS,
            "get_status_class": get_status_class,
            "name_filter": student_name or "",
            "group_filter": group or "",
            "type_filter": violation_type or "",
            "date_from_filter": date_from or "",
            "date_to_filter": date_to or "",
            "q_filter": q or "",
            "has_comment": hc,
            "status_filter": status or "",
            "get_badge_class": get_badge_class,
            "repeat_names": get_repeat_offenders(),
            "sort": sort,
            "dir": dir,
            "sort_urls": sort_urls,
            "page": page,
            "pages": pages,
            "total": total,
            "prev_url": prev_url,
            "next_url": next_url,
            "kpi": kpi,
            "today_str": today_str,
            "monday_str": monday_str,
        },
    )

@app.post("/admin/status/{violation_id}")
def admin_status_change(request: Request, violation_id: int, status: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    if status not in STATUS_LABELS:
        return toast_redirect("/admin", "Неизвестный статус")
    conn = get_db_connection()
    conn.execute("UPDATE violations SET status = ? WHERE id = ?", (status, violation_id))
    conn.commit()
    conn.close()
    log_action(request, "смена статуса", f"запись {violation_id} → {STATUS_LABELS[status]}")
    return toast_redirect("/admin", f"Статус: {STATUS_LABELS[status]}")

@app.post("/admin/bulk/delete")
def admin_bulk_delete(request: Request, ids: List[int] = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    for vid in ids:
        conn.execute("UPDATE violations SET deleted_at = ? WHERE id = ?", (now, vid))
    conn.commit()
    conn.close()
    log_action(request, "массовое удаление в корзину", f"записей: {len(ids)}")
    return toast_redirect("/admin", f"Перемещено в корзину: {len(ids)}")

@app.post("/admin/bulk/export")
def admin_bulk_export(request: Request, ids: List[int] = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    placeholders = ",".join("?" * len(ids))
    conn = get_db_connection()
    rows = conn.execute(
        f"SELECT * FROM violations WHERE id IN ({placeholders}) ORDER BY created_at DESC",
        ids,
    ).fetchall()
    conn.close()
    set_meta("last_export_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    log_action(request, "экспорт выбранных записей", f"записей: {len(ids)}")
    filename = f"violations_selected_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([render_csv(rows)]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.get("/admin/trash", response_class=HTMLResponse)
def admin_trash(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    cutoff = (datetime.now() - timedelta(days=TRASH_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    conn.execute("DELETE FROM violations WHERE deleted_at IS NOT NULL AND deleted_at < ?", (cutoff,))
    conn.commit()
    rows = conn.execute("SELECT * FROM violations WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC").fetchall()
    conn.close()
    return templates.TemplateResponse(
        "trash.html",
        {
            "request": request,
            "rows": rows,
            "get_badge_class": get_badge_class,
            "trash_days": TRASH_DAYS,
        },
    )

@app.post("/admin/trash/restore/{violation_id}")
def admin_trash_restore(request: Request, violation_id: int):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute("UPDATE violations SET deleted_at = NULL WHERE id = ?", (violation_id,))
    conn.commit()
    conn.close()
    log_action(request, "восстановление из корзины", f"запись {violation_id}")
    return toast_redirect("/admin/trash", "Запись восстановлена")

@app.post("/admin/trash/purge/{violation_id}")
def admin_trash_purge(request: Request, violation_id: int):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute("DELETE FROM violations WHERE id = ?", (violation_id,))
    conn.commit()
    conn.close()
    log_action(request, "окончательное удаление из корзины", f"запись {violation_id}")
    return toast_redirect("/admin/trash", "Запись удалена навсегда")

@app.get("/admin/audit", response_class=HTMLResponse)
def admin_audit(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return templates.TemplateResponse(
        "audit.html",
        {"request": request, "rows": rows},
    )

@app.get("/admin/add", response_class=HTMLResponse)
def admin_add_form(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    known = get_known_students()
    return templates.TemplateResponse(
        "admin_add.html",
        {
            "request": request,
            "violation_types": get_violation_types(),
            "known_students": sorted(known.keys()),
            "student_groups_json": json.dumps(known, ensure_ascii=False),
        },
    )

@app.post("/admin/add")
def admin_add_save(
    request: Request,
    student_group: str = Form(...),
    student_name: str = Form(...),
    violation_type: str = Form(...),
    comment: str = Form(""),
):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO violations
            (patrol_name, student_name, student_group, violation_type, comment, created_at, status)
        VALUES (?, ?, ?, ?, ?, ?, 'new')
        """,
        (ADMIN_LABEL, student_name.strip(), student_group.strip(), violation_type, comment.strip(), created_at),
    )
    conn.commit()
    conn.close()
    log_action(request, "добавлено нарушение админом", f"{student_name.strip()}, {student_group.strip()}, {violation_type}")
    return toast_redirect("/admin", "Запись добавлена от имени АДМИНИСТРАТОРА ✓")

@app.get("/admin/edit/{violation_id}", response_class=HTMLResponse)
def admin_edit_form(request: Request, violation_id: int):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM violations WHERE id = ?", (violation_id,)).fetchone()
    conn.close()
    if not row:
        return RedirectResponse(url="/admin", status_code=303)
    return templates.TemplateResponse(
        "edit.html",
        {"request": request, "v": row, "violation_types": get_violation_types()},
    )

@app.post("/admin/edit/{violation_id}")
def admin_edit_save(
    request: Request,
    violation_id: int,
    student_group: str = Form(...),
    student_name: str = Form(...),
    violation_type: str = Form(...),
    comment: str = Form(""),
):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute(
        "UPDATE violations SET student_group = ?, student_name = ?, violation_type = ?, comment = ? WHERE id = ?",
        (student_group.strip(), student_name.strip(), violation_type, comment.strip(), violation_id),
    )
    conn.commit()
    conn.close()
    log_action(request, "правка записи", f"запись {violation_id}: {student_name.strip()}")
    return toast_redirect("/admin", "Изменения сохранены ✓")

@app.post("/admin/delete/{violation_id}")
def admin_delete(request: Request, violation_id: int):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute(
        "UPDATE violations SET deleted_at = ? WHERE id = ?",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), violation_id),
    )
    conn.commit()
    conn.close()
    log_action(request, "удаление в корзину", f"запись {violation_id}")
    return toast_redirect("/admin", "Запись перемещена в корзину")

@app.post("/admin/restore")
async def admin_restore(request: Request, file: UploadFile = File(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    content = await file.read()
    text = content.decode("utf-8-sig")
    reader = csv.reader(io.StringIO(text), delimiter=";")
    rows = list(reader)
    if len(rows) < 2:
        return toast_redirect("/admin", "Файл пуст или не содержит записей")
    restored = 0
    skipped = 0
    conn = get_db_connection()
    for r in rows[1:]:
        if len(r) < 7:
            continue
        _, patrol_name, student_name, student_group, violation_type, comment, created_at = r[:7]
        if not student_name.strip():
            continue
        exists = conn.execute(
            "SELECT 1 FROM violations WHERE student_name = ? AND created_at = ? AND violation_type = ?",
            (student_name, created_at, violation_type),
        ).fetchone()
        if exists:
            skipped += 1
            continue
        conn.execute(
            """
            INSERT INTO violations
                (patrol_name, student_name, student_group, violation_type, comment, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, 'new')
            """,
            (patrol_name, student_name, student_group, violation_type, comment, created_at),
        )
        restored += 1
    conn.commit()
    conn.close()
    log_action(request, "восстановление из CSV", f"восстановлено {restored}, пропущено {skipped}")
    return toast_redirect("/admin", f"Восстановлено записей: {restored}" + (f", пропущено дубликатов: {skipped}" if skipped else ""))

@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings_page(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "deviant_min": get_deviant_min(),
            "deviants_reset_at": get_deviants_reset_at(),
            "violation_types": get_violation_types(),
            "departments": get_departments(),
        },
    )

@app.post("/admin/settings/pin")
def admin_settings_pin(request: Request, new_pin: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    new_pin = new_pin.strip()
    if len(new_pin) < 4:
        return toast_redirect("/admin/settings", "ПИН должен быть не короче 4 символов")
    set_meta("patrol_pin", new_pin)
    log_action(request, "смена ПИН патруля")
    return toast_redirect("/admin/settings", "ПИН патруля изменён")

@app.post("/admin/settings/password")
def admin_settings_password(request: Request, new_password: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    new_password = new_password.strip()
    if len(new_password) < 6:
        return toast_redirect("/admin/settings", "Пароль должен быть не короче 6 символов")
    set_meta("admin_password", new_password)
    log_action(request, "смена пароля администратора")
    return toast_redirect("/admin/settings", "Пароль администратора изменён")

@app.post("/admin/settings/deviants")
def admin_settings_deviants(request: Request, min_count: int = Form(2)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    set_meta("deviant_min", str(max(1, min_count)))
    log_action(request, "смена порога девианта", str(min_count))
    return toast_redirect("/admin/settings", "Порог девианта обновлён")

@app.post("/admin/settings/deviants/reset")
def admin_settings_deviants_reset(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    set_meta("deviants_reset_at", datetime.now().strftime("%Y-%m-%d"))
    log_action(request, "сброс девиантов", "учёт с " + datetime.now().strftime("%Y-%m-%d"))
    return toast_redirect("/admin/settings", "Девианты сброшены: учёт с сегодняшней даты")

@app.post("/admin/settings/types/add")
def admin_settings_type_add(request: Request, name: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    name = name.strip()
    if not name:
        return toast_redirect("/admin/settings", "Пустое название типа")
    types = get_violation_types()
    if name not in types:
        types.append(name)
        set_meta("violation_types", json.dumps(types, ensure_ascii=False))
        log_action(request, "добавлен тип нарушения", name)
    return toast_redirect("/admin/settings", "Тип нарушения добавлен")

@app.post("/admin/settings/types/delete")
def admin_settings_type_delete(request: Request, name: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    types = get_violation_types()
    if name in types and len(types) > 1:
        types.remove(name)
        set_meta("violation_types", json.dumps(types, ensure_ascii=False))
        log_action(request, "удалён тип нарушения", name)
    return toast_redirect("/admin/settings", "Тип нарушения удалён")

@app.post("/admin/settings/departments/add")
def admin_settings_department_add(request: Request, key: str = Form(...), name: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    key = key.strip().upper()
    name = name.strip()
    if not key or not name:
        return toast_redirect("/admin/settings", "Заполните префикс и название отделения")
    deps = get_departments()
    deps[key] = name
    set_meta("departments", json.dumps(deps, ensure_ascii=False))
    log_action(request, "добавлено отделение", f"{key} — {name}")
    return toast_redirect("/admin/settings", "Отделение добавлено")

@app.post("/admin/settings/departments/delete")
def admin_settings_department_delete(request: Request, key: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    deps = get_departments()
    if key in deps and len(deps) > 1:
        deps.pop(key)
        set_meta("departments", json.dumps(deps, ensure_ascii=False))
        log_action(request, "удалено отделение", key)
    return toast_redirect("/admin/settings", "Отделение удалено")

@app.get("/admin/quality", response_class=HTMLResponse)
def admin_quality(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    dep_keys = [k.casefold() for k in get_departments().keys()]
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM violations WHERE deleted_at IS NULL ORDER BY created_at DESC").fetchall()
    conn.close()

    bad_groups = sorted(
        {
            r["student_group"]
            for r in rows
            if not any(r["student_group"].strip().casefold().startswith(k) for k in dep_keys)
        }
    )
    empty_fields = [r for r in rows if not r["student_name"].strip() or not r["student_group"].strip()]

    spellings = {}
    for r in rows:
        spellings.setdefault(r["student_name"].casefold(), set()).add(r["student_name"])
    name_variants = sorted(
        [(cf, sorted(variants)) for cf, variants in spellings.items() if len(variants) > 1]
    )

    by_st = {}
    for r in rows:
        by_st.setdefault((r["student_name"], r["violation_type"]), []).append((r["created_at"][:10], r["id"]))
    dup_suspects = []
    for (nm, vt), pairs in by_st.items():
        pairs.sort()
        for (da, ia), (db, ib) in zip(pairs, pairs[1:]):
            d1 = datetime.strptime(da, "%Y-%m-%d")
            d2 = datetime.strptime(db, "%Y-%m-%d")
            if 0 <= (d2 - d1).days <= 3:
                dup_suspects.append({"name": nm, "type": vt, "dates": f"{da} / {db}", "later_id": ib})
                break

    year_ago = (datetime.now() - timedelta(days=365)).strftime("%Y-%m-%d")
    old_count = sum(1 for r in rows if r["created_at"][:10] < year_ago)

    return templates.TemplateResponse(
        "quality.html",
        {
            "request": request,
            "bad_groups": bad_groups[:50],
            "empty_fields": empty_fields[:50],
            "name_variants": name_variants[:50],
            "dup_suspects": dup_suspects[:50],
            "old_count": old_count,
            "total": len(rows),
        },
    )

@app.post("/admin/quality/dedup")
def admin_quality_dedup(request: Request, violation_id: int = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute(
        "UPDATE violations SET deleted_at = ? WHERE id = ?",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), violation_id),
    )
    conn.commit()
    conn.close()
    log_action(request, "удаление дубля из панели качества", f"запись {violation_id}")
    return toast_redirect("/admin/quality", "Дубль перемещён в корзину")

@app.get("/admin/dossier", response_class=HTMLResponse)
def admin_dossier(request: Request, name: str = ""):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    q = name.strip()
    data = None
    if q:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM violations WHERE deleted_at IS NULL ORDER BY created_at DESC").fetchall()
        conn.close()
        items = [r for r in rows if r["student_name"].casefold() == q.casefold()]
        if items:
            by_type = Counter(r["violation_type"] for r in items)
            by_month = Counter(r["created_at"][:7] for r in items)
            by_patrol = Counter(r["patrol_name"] for r in items)
            data = {
                "name": items[0]["student_name"],
                "records": items,
                "total": len(items),
                "by_type": by_type.most_common(),
                "by_month": sorted(by_month.items()),
                "by_patrol": by_patrol.most_common(),
                "groups": sorted({r["student_group"] for r in items}),
                "first": items[-1]["created_at"],
                "last": items[0]["created_at"],
            }
    return templates.TemplateResponse(
        "dossier.html",
        {"request": request, "data": data, "query": q, "get_badge_class": get_badge_class},
    )

@app.get("/admin/patrol", response_class=HTMLResponse)
def admin_patrol_page(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "patrol_manage.html",
        {"request": request, "names": get_patrol_names()},
    )

@app.post("/admin/patrol/add")
def admin_patrol_add(request: Request, name: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    name = name.strip()
    if name:
        conn = get_db_connection()
        conn.execute("INSERT OR IGNORE INTO patrol_members (name) VALUES (?)", (name,))
        conn.commit()
        conn.close()
        log_action(request, "добавлен патрульный", name)
    return toast_redirect("/admin/patrol", "Патрульный добавлен ✓")

@app.post("/admin/patrol/delete")
def admin_patrol_delete(request: Request, name: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute("DELETE FROM patrol_members WHERE name = ?", (name,))
    conn.commit()
    conn.close()
    log_action(request, "удалён патрульный", name)
    return toast_redirect("/admin/patrol", "Патрульный удалён")

@app.get("/admin/schedule", response_class=HTMLResponse)
def admin_schedule_page(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    today = datetime.now().strftime("%Y-%m-%d")
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM duty_schedule WHERE duty_date >= ? ORDER BY duty_date, id", (today,)
    ).fetchall()
    conn.close()
    schedule = {}
    for r in rows:
        schedule.setdefault(r["duty_date"], []).append(r["patrol_name"])
    return templates.TemplateResponse(
        "schedule.html",
        {
            "request": request,
            "names": get_patrol_names(),
            "schedule_list": sorted(schedule.items()),
            "today": today,
        },
    )

@app.post("/admin/schedule/add")
def admin_schedule_add(request: Request, duty_date: str = Form(...), names: List[str] = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    for n in names:
        conn.execute(
            "INSERT OR IGNORE INTO duty_schedule (duty_date, patrol_name) VALUES (?, ?)",
            (duty_date, n.strip()),
        )
    conn.commit()
    conn.close()
    log_action(request, "назначено дежурство", f"{duty_date}: {', '.join(names)}")
    return toast_redirect("/admin/schedule", "График сохранён ✓")

@app.post("/admin/schedule/delete")
def admin_schedule_delete(request: Request, duty_date: str = Form(...), name: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute("DELETE FROM duty_schedule WHERE duty_date = ? AND patrol_name = ?", (duty_date, name))
    conn.commit()
    conn.close()
    log_action(request, "снято дежурство", f"{duty_date}: {name}")
    return toast_redirect("/admin/schedule", "Убран из графика")

@app.get("/admin/shifts", response_class=HTMLResponse)
def admin_shifts_page(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    month_ago = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d") + " 00:00:00"
    conn = get_db_connection()
    closed = conn.execute(
        "SELECT * FROM shifts WHERE ended_at IS NOT NULL AND started_at >= ? ORDER BY started_at DESC",
        (month_ago,),
    ).fetchall()
    recent = conn.execute("SELECT * FROM shifts ORDER BY started_at DESC LIMIT 50").fetchall()
    conn.close()
    summary = {}
    for r in closed:
        s = summary.setdefault(r["patrol_name"], {"count": 0, "minutes": 0})
        s["count"] += 1
        s["minutes"] += r["duration_minutes"] or 0
    summary_list = sorted(
        [(name, s["count"], format_duration(s["minutes"])) for name, s in summary.items()],
        key=lambda x: x[1],
        reverse=True,
    )
    return templates.TemplateResponse(
        "shifts.html",
        {
            "request": request,
            "summary": summary_list,
            "recent": recent,
            "format_duration": format_duration,
        },
    )

@app.get("/admin/deviants", response_class=HTMLResponse)
def admin_deviants(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    min_count = get_deviant_min()
    reset = get_deviants_reset_at()

    query = "SELECT student_name, COUNT(*) AS c, MAX(created_at) AS last_date FROM violations WHERE deleted_at IS NULL"
    params: list = []
    if reset:
        query += " AND created_at >= ?"
        params.append(reset + " 00:00:00")
    query += " GROUP BY student_name HAVING COUNT(*) >= ? ORDER BY c DESC, student_name"
    params.append(min_count)

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    names = [r["student_name"] for r in rows]
    details = {}
    if names:
        placeholders = ",".join("?" * len(names))
        dquery = f"SELECT student_name, student_group, violation_type FROM violations WHERE deleted_at IS NULL AND student_name IN ({placeholders})"
        dparams: list = list(names)
        if reset:
            dquery += " AND created_at >= ?"
            dparams.append(reset + " 00:00:00")
        drows = conn.execute(dquery, dparams).fetchall()
        for d in drows:
            det = details.setdefault(d["student_name"], {"groups": set(), "types": Counter()})
            det["groups"].add(d["student_group"])
            det["types"][d["violation_type"]] += 1
    conn.close()

    deviants = []
    for r in rows:
        det = details.get(r["student_name"], {"groups": set(), "types": Counter()})
        top = det["types"].most_common(1)
        deviants.append(
            {
                "name": r["student_name"],
                "count": r["c"],
                "last_date": r["last_date"],
                "groups": ", ".join(sorted(det["groups"])),
                "top_type": top[0][0] if top else "",
            }
        )
    return templates.TemplateResponse(
        "deviants.html",
        {
            "request": request,
            "deviants": deviants,
            "total": len(deviants),
            "get_badge_class": get_badge_class,
            "deviant_min": min_count,
            "reset_label": reset,
        },
    )

@app.get("/admin/report", response_class=HTMLResponse)
def admin_report(
    request: Request,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    department: Optional[str] = None,
):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    now = datetime.now()
    if not date_from:
        date_from = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    if not date_to:
        date_to = now.strftime("%Y-%m-%d")

    departments = get_departments()
    query = "SELECT * FROM violations WHERE deleted_at IS NULL AND created_at >= ? AND created_at <= ?"
    params = [date_from + " 00:00:00", date_to + " 23:59:59"]
    if department:
        query += " AND student_group LIKE ?"
        params.append(f"{department}%")
    query += " ORDER BY created_at DESC"

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    by_type = Counter(r["violation_type"] for r in rows)
    top_groups = Counter(r["student_group"] for r in rows).most_common(3)

    lines = [
        f"СВОДКА за период с {date_from} по {date_to}" + (f" ({departments.get(department, '')})" if department else ""),
        f"Всего нарушений: {len(rows)}",
        "По типам: " + ("; ".join(f"{t} — {c}" for t, c in by_type.most_common()) if by_type else "нет данных"),
    ]
    if top_groups:
        lines.append("Топ групп: " + ", ".join(f"{g} ({c})" for g, c in top_groups))
    lines.append(f"Сформировано: {now.strftime('%d.%m.%Y %H:%M')}")
    summary_text = "\n".join(lines)

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "rows": rows,
            "period_start": date_from,
            "period_end": date_to,
            "generated": now.strftime("%d.%m.%Y %H:%M"),
            "total": len(rows),
            "by_type": by_type.most_common(),
            "get_badge_class": get_badge_class,
            "departments": departments,
            "dept_filter": department or "",
            "dept_name": departments.get(department or "", ""),
            "summary_text": summary_text,
        },
    )

@app.get("/admin/export")
def admin_export(
    request: Request,
    student_name: Optional[str] = None,
    group: Optional[str] = None,
    violation_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    q: Optional[str] = None,
    has_comment: Optional[str] = None,
    status: Optional[str] = None,
):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    query, params = build_violations_query(student_name, group, violation_type, date_from, date_to, q=q, has_comment=bool(has_comment), status=status)
    query += " ORDER BY created_at DESC, id DESC"
    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    set_meta("last_export_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    log_action(request, "экспорт CSV", f"записей: {len(rows)}")
    filename = f"violations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([render_csv(rows)]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

# ---------------------------------------------------------------------------
# Статистика
# ---------------------------------------------------------------------------
@app.get("/stats", response_class=HTMLResponse)
def stats_page(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM violations WHERE deleted_at IS NULL").fetchall()
    conn.close()

    departments = get_departments()
    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    month_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    this_monday = (now - timedelta(days=now.weekday())).strftime("%Y-%m-%d")
    last_monday = (now - timedelta(days=now.weekday() + 7)).strftime("%Y-%m-%d")

    days = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(13, -1, -1)]
    heat_days = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(179, -1, -1)]
    by_day = {d: 0 for d in days}
    heat = {d: 0 for d in heat_days}
    by_type = Counter()
    by_group = Counter()
    by_patrol = Counter()
    by_weekday = Counter()
    by_hour = Counter()
    by_dept = Counter()
    by_student = Counter()
    student_info = {}
    weekday_history = {}

    total = len(rows)
    today_count = 0
    week_count = 0
    month_count = 0
    this_week_count = 0
    last_week_count = 0

    for row in rows:
        day = row["created_at"][:10]
        dt = datetime.strptime(day, "%Y-%m-%d")
        wd = dt.weekday()
        if day == today_str:
            today_count += 1
        if day >= week_ago:
            week_count += 1
        if day >= month_ago:
            month_count += 1
        if day in by_day:
            by_day[day] += 1
        if day in heat:
            heat[day] += 1
        if day >= this_monday:
            this_week_count += 1
        elif day >= last_monday:
            last_week_count += 1
        by_weekday[wd] += 1
        try:
            by_hour[int(row["created_at"][11:13])] += 1
        except (ValueError, IndexError):
            pass
        dept = next((k for k in departments if row["student_group"].upper().startswith(k)), "other")
        by_dept[dept] += 1
        by_type[row["violation_type"]] += 1
        by_group[row["student_group"]] += 1
        by_patrol[row["patrol_name"]] += 1
        by_student[row["student_name"]] += 1
        info = student_info.setdefault(row["student_name"], {"groups": set(), "last": day})
        info["groups"].add(row["student_group"])
        if day > info["last"]:
            info["last"] = day
        rec = weekday_history.setdefault(wd, {"days": set(), "count": 0, "groups": Counter(), "types": Counter()})
        rec["days"].add(day)
        rec["count"] += 1
        rec["groups"][row["student_group"]] += 1
        rec["types"][row["violation_type"]] += 1

    if last_week_count > 0:
        week_delta = round((this_week_count - last_week_count) / last_week_count * 100)
    else:
        week_delta = None

    hours = list(range(7, 21))
    top_groups = by_group.most_common(5)
    top_students = []
    for name, c in by_student.most_common(10):
        info = student_info[name]
        top_students.append(
            {
                "name": name,
                "count": c,
                "groups": ", ".join(sorted(info["groups"])),
                "last": info["last"],
            }
        )

    cur_wd = now.weekday()
    rec = weekday_history.get(cur_wd)
    risk_predicted = 0
    risk_group = ""
    risk_type = ""
    if rec and rec["days"]:
        risk_predicted = round(rec["count"] / len(rec["days"]))
        risk_group = rec["groups"].most_common(1)[0][0] if rec["groups"] else ""
        risk_type = rec["types"].most_common(1)[0][0] if rec["types"] else ""

    dept_keys = list(departments.keys()) + ["other"]
    chart_data = {
        "days_labels": [d[5:] for d in days],
        "days_counts": [by_day[d] for d in days],
        "type_labels": list(by_type.keys()),
        "type_counts": list(by_type.values()),
        "group_labels": [g for g, _ in top_groups],
        "group_counts": [c for _, c in top_groups],
        "weekday_labels": ["ПН", "ВТ", "СР", "ЧТ", "ПТ", "СБ", "ВС"],
        "weekday_counts": [by_weekday.get(i, 0) for i in range(7)],
        "hour_labels": [str(h) for h in hours],
        "hour_counts": [by_hour.get(h, 0) for h in hours],
        "dept_labels": [departments.get(k, k) for k in dept_keys],
        "dept_counts": [by_dept.get(k, 0) for k in dept_keys],
        "heat": [{"d": d, "c": heat[d]} for d in heat_days],
    }

    return templates.TemplateResponse(
        "stats.html",
        {
            "request": request,
            "total": total,
            "today_count": today_count,
            "week_count": week_count,
            "month_count": month_count,
            "this_week_count": this_week_count,
            "last_week_count": last_week_count,
            "week_delta": week_delta,
            "top_patrols": by_patrol.most_common(),
            "top_students": top_students,
            "risk_weekday": ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"][cur_wd],
            "risk_predicted": risk_predicted,
            "risk_group": risk_group,
            "risk_type": risk_type,
            "deviant_min": get_deviant_min(),
            "get_badge_class": get_badge_class,
            "chart_data_json": json.dumps(chart_data, ensure_ascii=False),
        },
    )

# ---------------------------------------------------------------------------
# Волна 3: оперативный монитор «Штаб»
# ---------------------------------------------------------------------------
@app.get("/hq", response_class=HTMLResponse)
def hq_page(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("hq.html", {"request": request})

@app.get("/hq/data")
def hq_data(request: Request):
    if not is_admin(request):
        return HTMLResponse(content=json.dumps({"ok": False}), media_type="application/json", status_code=403)
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    conn = get_db_connection()
    today_count = conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NULL AND created_at >= ?", (today + " 00:00:00",)).fetchone()[0]
    week_count = conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NULL AND created_at >= ?", (week_ago + " 00:00:00",)).fetchone()[0]
    feed_rows = conn.execute("SELECT * FROM violations WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 12").fetchall()
    duty_rows = conn.execute("SELECT patrol_name FROM duty_schedule WHERE duty_date = ?", (today,)).fetchall()
    open_shifts = conn.execute("SELECT COUNT(*) FROM shifts WHERE ended_at IS NULL").fetchone()[0]
    conn.close()
    feed = [
        {
            "time": r["created_at"][11:16],
            "group": r["student_group"],
            "type": r["violation_type"],
            "patrol": r["patrol_name"],
        }
        for r in feed_rows
    ]
    return HTMLResponse(
        content=json.dumps(
            {
                "ok": True,
                "today": today_count,
                "week": week_count,
                "on_duty": [r["patrol_name"] for r in duty_rows],
                "open_shifts": open_shifts,
                "feed": feed,
                "clock": now.strftime("%d.%m.%Y %H:%M:%S"),
            },
            ensure_ascii=False,
        ),
        media_type="application/json",
    )
