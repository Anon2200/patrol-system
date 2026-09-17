from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo
import io
import csv
import urllib.parse

app = FastAPI()
templates = Jinja2Templates(directory="templates")

DB_NAME = "patrol.db"
ADMIN_PASSWORD = "1029384756"

# База патрульных: ПИН-код -> ФИО
PATROLS = {
    "1111": "Борисов",
    "2222": "Соколов",
    "3333": "Ипполитов",
    "4444": "Старовойтов",
    "5555": "Алёшин",
    "6666": "Иванов",
    "7777": "Нилов",
    "8888": "Дрейден",
    "9999": "Лунев",
    "1212": "Халин",
    "3434": "Позднякова",
    "5656": "Глущенко"
}

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patrol_name TEXT NOT NULL,
            student_name TEXT NOT NULL,
            student_group TEXT NOT NULL,
            violation_type TEXT NOT NULL,
            comment TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def is_admin(request: Request):
    return request.cookies.get("auth_role") == "admin"

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, success: str = None, error: str = None):
    patrol_name = request.cookies.get("patrol_name")
    patrols_list = sorted(list(PATROLS.values()))
    return templates.TemplateResponse("patrol.html", {
        "request": request, 
        "patrol_name": patrol_name,
        "patrols_list": patrols_list,
        "success": success,
        "error": error
    })

@app.post("/patrol/login")
async def patrol_login(patrol_name: str = Form(...), pin: str = Form(...)):
    if pin in PATROLS and PATROLS[pin] == patrol_name:
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="patrol_name", value=patrol_name, max_age=86400*30, httponly=True)
        return response
    return RedirectResponse(url="/?error=1", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/patrol/logout")
async def patrol_logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("patrol_name")
    return response

@app.post("/add")
async def add_violation(
    request: Request,
    student_name: str = Form(...),
    student_group: str = Form(...),
    violation_type: str = Form(...),
    comment: str = Form(""),
    db: sqlite3.Connection = Depends(get_db)
):
    patrol_name = request.cookies.get("patrol_name")
    if not patrol_name:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    # Время по Москве (Europe/Moscow)
    created_at = datetime.now(ZoneInfo("Europe/Moscow")).strftime("%Y-%m-%d %H:%M:%S")
    
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO violations (patrol_name, student_name, student_group, violation_type, comment, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (patrol_name, student_name, student_group, violation_type, comment, created_at)
    )
    db.commit()
    return RedirectResponse(url="/?success=1", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    if is_admin(request):
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request, "error": error})

@app.post("/login")
async def login_post(password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        response = RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="auth_role", value="admin", httponly=True)
        return response
    return RedirectResponse(url="/login?error=1", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("auth_role")
    return response

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(
    request: Request,
    student_name: str = "",
    violation_type: str = "",
    db: sqlite3.Connection = Depends(get_db)
):
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    query = "SELECT * FROM violations WHERE 1=1"
    params = []

    if student_name:
        query += " AND student_name LIKE ?"
        params.append(f"%{student_name.strip()}%")
    if violation_type:
        query += " AND violation_type = ?"
        params.append(violation_type)

    query += " ORDER BY id DESC"

    cursor = db.cursor()
    cursor.execute(query, params)
    violations = cursor.fetchall()

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "violations": violations,
            "selected_student": student_name,
            "selected_type": violation_type
        }
    )

@app.get("/admin/export")
async def export_csv(
    request: Request,
    student_name: str = "",
    violation_type: str = "",
    db: sqlite3.Connection = Depends(get_db)
):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    query = "SELECT id, created_at, patrol_name, student_group, student_name, violation_type, comment FROM violations WHERE 1=1"
    params = []

    if student_name:
        query += " AND student_name LIKE ?"
        params.append(f"%{student_name.strip()}%")
    if violation_type:
        query += " AND violation_type = ?"
        params.append(violation_type)

    query += " ORDER BY id DESC"

    cursor = db.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()

    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output, delimiter=';')
    writer.writerow(["ID", "Дата/Время (МСК)", "Патрульный", "Группа", "ФИО Студента", "Тип нарушения", "Комментарий"])

    for row in rows:
        writer.writerow(list(row))

    output.seek(0)
    filename = urllib.parse.quote(f"violations_report_{datetime.now(ZoneInfo('Europe/Moscow')).strftime('%Y%m%d_%H%M%S')}.csv")

    return StreamingResponse(
        io.BytesIO(output.getvalue().encode('utf-8')),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename}"}
    )

@app.post("/admin/delete/{violation_id}")
async def delete_violation(
    violation_id: int,
    request: Request,
    db: sqlite3.Connection = Depends(get_db)
):
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    cursor = db.cursor()
    cursor.execute("DELETE FROM violations WHERE id = ?", (violation_id,))
    db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
