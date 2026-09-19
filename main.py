import csv
import io
import json
import os
import sqlite3
import urllib.parse
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_DIR = Path(os.environ.get("DB_DIR", str(BASE_DIR)))
DB_PATH = DB_DIR / "patrol.db"

DEFAULT_PATROL_NAMES = [
    "Борисов",
    "Соколов",
    "Ипполитов",
    "Старовойтов",
    "Алёшин",
    "Иванов",
    "Нилов",
    "Дрейден",
    "Лунев",
    "Халин",
    "Позднякова",
    "Глущенко",
]

PATROL_PIN = "1234"
ADMIN_PASSWORD = "1029384756"

VIOLATION_TYPES = [
    "Опоздание",
    "Отсутствие формы / бейджа",
    "Нарушение дисциплины",
    "Курение в неположенном месте",
    "Другое",
]

VIOLATION_COLORS = {
    "Опоздание": "orange",
    "Отсутствие формы / бейджа": "yellow",
    "Нарушение дисциплины": "red",
    "Курение в неположенном месте": "darkred",
    "Другое": "gray",
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
# База данных
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
# Страницы ошибок (404 / 500)
# ---------------------------------------------------------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    message = "Страница не найдена." if exc.status_code == 404 else str(exc.detail)
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "code": exc.status_code, "message": message},
        status_code=exc.status_code,
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "code": 500, "message": "Внутренняя ошибка сервера. Попробуйте обновить страницу позже."},
        status_code=500,
    )

# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------
def is_admin(request: Request) -> bool:
    return request.cookies.get(COOKIE_AUTH_ROLE) == "admin"

def get_patrol_names():
    conn = get_db_connection()
    rows = conn.execute("SELECT name FROM patrol_members ORDER BY id").fetchall()
    conn.close()
    return [r["name"] for r in rows]

def get_patrol_name(request: Request) -> Optional[str]:
    raw_name = request.cookies.get(COOKIE_PATROL_NAME)
    if not raw_name:
        return None
    name = urllib.parse.unquote(raw_name)
    if name in get_patrol_names():
        return name
    return None

def get_badge_class(violation_type: str) -> str:
    return f"badge badge-{VIOLATION_COLORS.get(violation_type, 'gray')}"

def get_repeat_offenders(min_count: int = 3):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT student_name FROM violations GROUP BY student_name HAVING COUNT(*) >= ?",
        (min_count,),
    ).fetchall()
    conn.close()
    return [r["student_name"] for r in rows]

def get_known_students():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT student_name, student_group FROM violations ORDER BY id DESC"
    ).fetchall()
    conn.close()
    known = {}
    for row in rows:
        known.setdefault(row["student_name"], row["student_group"])
    return known

def build_violations_query(student_name, violation_type, date_from, date_to):
    query = "SELECT * FROM violations WHERE 1=1"
    params = []
    if student_name:
        query += " AND student_name LIKE ?"
        params.append(f"%{student_name}%")
    if violation_type:
        query += " AND violation_type = ?"
        params.append(violation_type)
    if date_from:
        query += " AND created_at >= ?"
        params.append(f"{date_from} 00:00:00")
    if date_to:
        query += " AND created_at <= ?"
        params.append(f"{date_to} 23:59:59")
    return query, params

def toast_redirect(url: str, message: str) -> RedirectResponse:
    return RedirectResponse(url + "?toast=" + urllib.parse.quote(message), status_code=303)

# ---------------------------------------------------------------------------
# Маршруты патрульного
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def patrol_home(request: Request):
    patrol_name = get_patrol_name(request)
    if not patrol_name:
        return templates.TemplateResponse(
            "patrol.html",
            {
                "request": request,
                "logged_in": False,
                "patrol_names": get_patrol_names(),
                "error": None,
            },
        )
    known = get_known_students()
    return templates.TemplateResponse(
        "patrol.html",
        {
            "request": request,
            "logged_in": True,
            "patrol_name": patrol_name,
            "violation_types": VIOLATION_TYPES,
            "known_students": sorted(known.keys()),
            "student_groups_json": json.dumps(known, ensure_ascii=False),
        },
    )

@app.post("/patrol/login")
def patrol_login(
    request: Request,
    patrol_name: str = Form(...),
    pin: str = Form(...),
):
    names = get_patrol_names()
    if patrol_name not in names or pin != PATROL_PIN:
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
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key=COOKIE_PATROL_NAME,
        value=urllib.parse.quote(patrol_name),
        max_age=COOKIE_MAX_AGE_30_DAYS,
        httponly=True,
        samesite="lax",
    )
    return response

@app.get("/patrol/logout")
def patrol_logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(COOKIE_PATROL_NAME)
    return response

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
        "SELECT id FROM violations WHERE lower(student_name) = lower(?) AND violation_type = ? AND created_at >= ?",
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
                "violation_types": VIOLATION_TYPES,
                "known_students": sorted(known.keys()),
                "student_groups_json": json.dumps(known, ensure_ascii=False),
                "dup_warning": f"Сегодня уже записано нарушение «{violation_type}» для студента {student_name_clean}. Сохранить ещё раз?",
                "form_group": student_group.strip(),
                "form_name": student_name_clean,
                "form_type": violation_type,
                "form_comment": comment.strip(),
            },
        )

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """
        INSERT INTO violations
            (patrol_name, student_name, student_group, violation_type, comment, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (patrol_name, student_name_clean, student_group.strip(), violation_type, comment.strip(), created_at),
    )
    conn.commit()
    conn.close()
    return toast_redirect("/", "Нарушение сохранено ✓")

# ---------------------------------------------------------------------------
# Маршруты администратора
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
    if password != ADMIN_PASSWORD:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный пароль. Попробуйте ещё раз."},
            status_code=400,
        )
    response = RedirectResponse(url="/admin", status_code=303)
    response.set_cookie(
        key=COOKIE_AUTH_ROLE,
        value="admin",
        httponly=True,
        samesite="lax",
    )
    return response

@app.get("/admin/logout")
def admin_logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(COOKIE_AUTH_ROLE)
    return response

@app.get("/admin", response_class=HTMLResponse)
def admin_panel(
    request: Request,
    student_name: Optional[str] = None,
    violation_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
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

    query, params = build_violations_query(student_name, violation_type, date_from, date_to)
    conn = get_db_connection()
    total = conn.execute(query.replace("SELECT *", "SELECT COUNT(*)", 1), params).fetchone()[0]
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(max(1, page), pages)
    rows = conn.execute(
        query + f" ORDER BY {sort} {dir.upper()}, id DESC LIMIT ? OFFSET ?",
        params + [PER_PAGE, (page - 1) * PER_PAGE],
    ).fetchall()
    conn.close()

    base_params = {
        "student_name": student_name or "",
        "violation_type": violation_type or "",
        "date_from": date_from or "",
        "date_to": date_to or "",
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
            "violation_types": VIOLATION_TYPES,
            "name_filter": student_name or "",
            "type_filter": violation_type or "",
            "date_from_filter": date_from or "",
            "date_to_filter": date_to or "",
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
        },
    )

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
        {"request": request, "v": row, "violation_types": VIOLATION_TYPES},
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
    return toast_redirect("/admin", "Изменения сохранены ✓")

@app.post("/admin/delete/{violation_id}")
def admin_delete(request: Request, violation_id: int):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute("DELETE FROM violations WHERE id = ?", (violation_id,))
    conn.commit()
    conn.close()
    return toast_redirect("/admin", "Запись удалена")

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
    return toast_redirect("/admin/patrol", "Патрульный добавлен ✓")

@app.post("/admin/patrol/delete")
def admin_patrol_delete(request: Request, name: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    conn = get_db_connection()
    conn.execute("DELETE FROM patrol_members WHERE name = ?", (name,))
    conn.commit()
    conn.close()
    return toast_redirect("/admin/patrol", "Патрульный удалён")

@app.get("/admin/report", response_class=HTMLResponse)
def admin_report(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    now = datetime.now()
    start = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM violations WHERE created_at >= ? ORDER BY created_at DESC",
        (start + " 00:00:00",),
    ).fetchall()
    conn.close()
    by_type = Counter(r["violation_type"] for r in rows)
    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "rows": rows,
            "period_start": start,
            "period_end": now.strftime("%Y-%m-%d"),
            "generated": now.strftime("%d.%m.%Y %H:%M"),
            "total": len(rows),
            "by_type": by_type.most_common(),
            "get_badge_class": get_badge_class,
        },
    )

@app.get("/admin/export")
def admin_export(
    request: Request,
    student_name: Optional[str] = None,
    violation_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    query, params = build_violations_query(student_name, violation_type, date_from, date_to)
    query += " ORDER BY created_at DESC, id DESC"
    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    buffer = io.StringIO()
    buffer.write("\ufeff")
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow(
        ["ID", "Патрульный", "ФИО студента", "Группа", "Тип нарушения", "Комментарий", "Дата и время"]
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
            ]
        )
    buffer.seek(0)
    filename = f"violations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

# ---------------------------------------------------------------------------
# Статистика (дашборд)
# ---------------------------------------------------------------------------
@app.get("/stats", response_class=HTMLResponse)
def stats_page(request: Request):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM violations").fetchall()
    conn.close()

    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    month_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")

    days = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(13, -1, -1)]
    by_day = {d: 0 for d in days}
    by_type = Counter()
    by_group = Counter()
    by_patrol = Counter()

    total = len(rows)
    today_count = 0
    week_count = 0
    month_count = 0

    for row in rows:
        day = row["created_at"][:10]
        if day == today_str:
            today_count += 1
        if day >= week_ago:
            week_count += 1
        if day >= month_ago:
            month_count += 1
        if day in by_day:
            by_day[day] += 1
        by_type[row["violation_type"]] += 1
        by_group[row["student_group"]] += 1
        by_patrol[row["patrol_name"]] += 1

    top_groups = by_group.most_common(5)

    chart_data = {
        "days_labels": [d[5:] for d in days],
        "days_counts": [by_day[d] for d in days],
        "type_labels": list(by_type.keys()),
        "type_counts": list(by_type.values()),
        "group_labels": [g for g, _ in top_groups],
        "group_counts": [c for _, c in top_groups],
    }

    return templates.TemplateResponse(
        "stats.html",
        {
            "request": request,
            "total": total,
            "today_count": today_count,
            "week_count": week_count,
            "month_count": month_count,
            "top_patrols": by_patrol.most_common(),
            "chart_data_json": json.dumps(chart_data, ensure_ascii=False),
        },
    )
