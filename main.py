import csv
import io
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "patrol.db"

PATROL_NAMES = [
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

COOKIE_PATROL_NAME = "patrol_name"
COOKIE_AUTH_ROLE = "auth_role"
COOKIE_MAX_AGE_30_DAYS = 60 * 60 * 24 * 30

app = FastAPI(title="Патрульная служба колледжа")
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
    conn.commit()
    conn.close()

@app.on_event("startup")
def on_startup() -> None:
    init_db()

# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------
def is_admin(request: Request) -> bool:
    return request.cookies.get(COOKIE_AUTH_ROLE) == "admin"

def get_patrol_name(request: Request) -> Optional[str]:
    name = request.cookies.get(COOKIE_PATROL_NAME)
    if name in PATROL_NAMES:
        return name
    return None

# ---------------------------------------------------------------------------
# Маршруты патрульного
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def patrol_home(request: Request, success: Optional[str] = None):
    patrol_name = get_patrol_name(request)
    if not patrol_name:
        return templates.TemplateResponse(
            "patrol.html",
            {
                "request": request,
                "logged_in": False,
                "patrol_names": PATROL_NAMES,
                "error": None,
            },
        )
    return templates.TemplateResponse(
        "patrol.html",
        {
            "request": request,
            "logged_in": True,
            "patrol_name": patrol_name,
            "violation_types": VIOLATION_TYPES,
            "success": success,
        },
    )

@app.post("/patrol/login")
def patrol_login(
    request: Request,
    patrol_name: str = Form(...),
    pin: str = Form(...),
):
    if patrol_name not in PATROL_NAMES or pin != PATROL_PIN:
        return templates.TemplateResponse(
            "patrol.html",
            {
                "request": request,
                "logged_in": False,
                "patrol_names": PATROL_NAMES,
                "error": "Неверное ФИО или ПИН-код. Попробуйте ещё раз.",
            },
            status_code=400,
        )
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key=COOKIE_PATROL_NAME,
        value=patrol_name,
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
):
    patrol_name = get_patrol_name(request)
    if not patrol_name:
        return RedirectResponse(url="/", status_code=303)

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO violations
            (patrol_name, student_name, student_group, violation_type, comment, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (patrol_name, student_name.strip(), student_group.strip(), violation_type, comment.strip(), created_at),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/?success=1", status_code=303)

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
):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)

    query = "SELECT * FROM violations WHERE 1=1"
    params = []
    if student_name:
        query += " AND student_name LIKE ?"
        params.append(f"%{student_name}%")
    if violation_type:
        query += " AND violation_type = ?"
        params.append(violation_type)
    query += " ORDER BY created_at DESC, id DESC"

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "violations": rows,
            "violation_types": VIOLATION_TYPES,
            "name_filter": student_name or "",
            "type_filter": violation_type or "",
        },
    )

@app.post("/admin/delete/{violation_id}")
def admin_delete(request: Request, violation_id: int):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)

    conn = get_db_connection()
    conn.execute("DELETE FROM violations WHERE id = ?", (violation_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=303)

@app.get("/admin/export")
def admin_export(
    request: Request,
    student_name: Optional[str] = None,
    violation_type: Optional[str] = None,
):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=303)

    query = "SELECT * FROM violations WHERE 1=1"
    params = []
    if student_name:
        query += " AND student_name LIKE ?"
        params.append(f"%{student_name}%")
    if violation_type:
        query += " AND violation_type = ?"
        params.append(violation_type)
    query += " ORDER BY created_at DESC, id DESC"

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    buffer = io.StringIO()
    buffer.write("\ufeff")  # UTF-8 BOM для корректного открытия в Excel
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow(
        [
            "ID",
            "Патрульный",
            "ФИО студента",
            "Группа",
            "Тип нарушения",
            "Комментарий",
            "Дата и время",
        ]
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
