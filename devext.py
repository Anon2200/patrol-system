# ---------------------------------------------------------------------------
# Служебные расширения разработчика: журнал запросов, нагрузка маршрутов,
# health и самотест, режим техработ, флаги функций, тревожные студенты,
# докладная записка, почтовая рассылка тревожных сводок.
# Подключается из main.py: import devext; devext.register(app, templates)
# ---------------------------------------------------------------------------
import json
import os
import smtplib
import threading
import time
from collections import Counter
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Optional

from fastapi import Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import main as M

_TPL = None

MAINTENANCE_PAGE = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Технические работы</title>
<style>
body { margin: 0; background: #0a0e13; color: #d8dee6; font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.box { max-width: 520px; margin: 20px; padding: 36px; border: 1px solid #2a3644; border-radius: 4px; background: #111820; text-align: center; }
h1 { font-size: 18px; letter-spacing: 0.2em; text-transform: uppercase; color: #c8a24a; }
p { color: #8593a2; line-height: 1.7; font-size: 14px; }
</style></head>
<body><div class="box">
<h1>Технические работы</h1>
<p>Система патрульной службы временно недоступна: ведутся плановые работы.</p>
<p>Данные в безопасности. Попробуйте позже или обратитесь к разработчику системы.</p>
</div></body></html>"""

# ---------------------------------------------------------------------------
# Промежуточные слои
# ---------------------------------------------------------------------------
async def access_log_mw(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    try:
        ms = int((time.time() - start) * 1000)
        conn = M.get_db_connection()
        conn.execute(
            "INSERT INTO access_log (ts, ip, method, path, status, ms) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), M.get_client_ip(request), request.method, request.url.path, response.status_code, ms),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
    return response

async def maintenance_mw(request: Request, call_next):
    path = request.url.path
    if M.get_meta("maintenance", "0") == "1":
        if not path.startswith("/dev") and not path.startswith("/static") and path not in ("/sw.js", "/manifest.webmanifest"):
            role = M.verify_signed(request.cookies.get(M.COOKIE_AUTH_ROLE))
            if role != "dev":
                return HTMLResponse(content=MAINTENANCE_PAGE, status_code=503)
    return await call_next(request)

# ---------------------------------------------------------------------------
# Служебные страницы разработчика
# ---------------------------------------------------------------------------
def dev_health(request: Request):
    ok = True
    try:
        conn = M.get_db_connection()
        conn.execute("SELECT COUNT(*) FROM meta").fetchone()
        conn.close()
    except Exception:
        ok = False
    return HTMLResponse(
        content=json.dumps({"ok": ok, "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "version": M.APP_VERSION}, ensure_ascii=False),
        media_type="application/json",
    )

def dev_monitor(request: Request):
    if not M.is_dev(request):
        return RedirectResponse(url="/dev/login", status_code=303)
    conn = M.get_db_connection()
    conn.execute("DELETE FROM access_log WHERE id NOT IN (SELECT id FROM access_log ORDER BY id DESC LIMIT 500)")
    conn.commit()
    recent = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 100").fetchall()
    cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    routes = conn.execute(
        "SELECT path, COUNT(*) AS hits, AVG(ms) AS avg_ms, MAX(ms) AS max_ms FROM access_log WHERE ts >= ? GROUP BY path ORDER BY hits DESC LIMIT 30",
        (cutoff,),
    ).fetchall()
    conn.close()
    return _TPL.TemplateResponse(
        "dev_monitor.html",
        {"request": request, "recent": recent, "routes": routes},
    )

def dev_selftest(request: Request):
    if not M.is_dev(request):
        return RedirectResponse(url="/dev/login", status_code=303)
    checks = []

    def add(name, ok, comment=""):
        checks.append({"name": name, "ok": bool(ok), "comment": comment})

    add("Файл базы существует", os.path.exists(M.DB_PATH), str(M.DB_PATH))
    add("Каталог базы доступен для записи", os.access(M.DB_DIR, os.W_OK), str(M.DB_DIR))
    try:
        conn = M.get_db_connection()
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        required = ["violations", "patrol_members", "duty_schedule", "shifts", "meta", "error_log", "audit_log", "access_log"]
        missing = [t for t in required if t not in tables]
        add("Все обязательные таблицы на месте", not missing, ", ".join(missing) if missing else f"{len(required)} таблиц")
    except Exception as e:
        add("Все обязательные таблицы на месте", False, repr(e))
    try:
        M.get_meta("session_salt")
        add("Таблица meta читается", True)
    except Exception as e:
        add("Таблица meta читается", False, repr(e))
    add("Файл стилей на месте", os.path.exists(M.BASE_DIR / "static" / "styles.css"))
    tpl_dir = M.BASE_DIR / "templates"
    missing_tpl = [f for f in ["admin.html", "patrol.html", "login.html", "sidebar.html"] if not (tpl_dir / f).exists()]
    add("Ключевые шаблоны на месте", not missing_tpl, ", ".join(missing_tpl) if missing_tpl else "")
    add("SMTP для рассылки настроен", bool(os.environ.get("SMTP_HOST")), os.environ.get("SMTP_HOST") or "переменная SMTP_HOST не задана")
    add("Токен бота MAX задан", bool(os.environ.get("MAX_BOT_TOKEN")), "" if os.environ.get("MAX_BOT_TOKEN") else "бот не запущен")
    add("Пароль разработчика изменён", M.get_dev_password() != "developer", "" if M.get_dev_password() != "developer" else "стоит пароль по умолчанию")
    return _TPL.TemplateResponse(
        "dev_selftest.html",
        {"request": request, "checks": checks, "version": M.APP_VERSION},
    )

def dev_controls(request: Request):
    if not M.is_dev(request):
        return RedirectResponse(url="/dev/login", status_code=303)
    return _TPL.TemplateResponse(
        "dev_controls.html",
        {
            "request": request,
            "maintenance": M.get_meta("maintenance", "0") == "1",
            "flags": M.get_flags(),
        },
    )

def dev_controls_maintenance(request: Request, state: str = Form(...)):
    if not M.is_dev(request):
        return RedirectResponse(url="/dev/login", status_code=303)
    value = "1" if state == "on" else "0"
    M.set_meta("maintenance", value)
    M.log_action(request, "режим техработ", "включён" if value == "1" else "выключен")
    return M.toast_redirect("/dev/controls", "Режим техработ: " + ("включён" if value == "1" else "выключен"))

async def dev_controls_flags_post(request: Request):
    if not M.is_dev(request):
        return RedirectResponse(url="/dev/login", status_code=303)
    form = await request.form()
    flags = {key: (form.get(key) == "on") for key in ["offline_queue", "live_check", "dup_control", "hq_refresh"]}
    M.set_meta("feature_flags", json.dumps(flags, ensure_ascii=False))
    M.log_action(request, "смена флагов функций", ", ".join(f"{k}={'1' if v else '0'}" for k, v in flags.items()))
    return M.toast_redirect("/dev/controls", "Флаги функций сохранены")

# ---------------------------------------------------------------------------
# Тревожные студенты и докладная
# ---------------------------------------------------------------------------
def compute_alerts():
    now = datetime.now()
    week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    today = now.strftime("%Y-%m-%d")
    conn = M.get_db_connection()
    week_rows = conn.execute(
        "SELECT * FROM violations WHERE deleted_at IS NULL AND created_at >= ?",
        (week_ago + " 00:00:00",),
    ).fetchall()
    conn.close()
    agg = {}
    for r in week_rows:
        a = agg.setdefault(r["student_name"], {"count": 0, "types": set(), "groups": set(), "last": "", "today_types": set()})
        a["count"] += 1
        a["types"].add(r["violation_type"])
        a["groups"].add(r["student_group"])
        if r["created_at"] > a["last"]:
            a["last"] = r["created_at"]
        if r["created_at"][:10] == today:
            a["today_types"].add(r["violation_type"])
    alerts = []
    for name, a in agg.items():
        reasons = []
        if a["count"] >= 3:
            reasons.append(f"{a['count']} нарушения за 7 дней")
        if len(a["today_types"]) >= 2:
            reasons.append("разные типы нарушений за один день")
        if reasons:
            alerts.append(
                {
                    "name": name,
                    "count": a["count"],
                    "groups": ", ".join(sorted(a["groups"])),
                    "types": ", ".join(sorted(a["types"])),
                    "last": a["last"],
                    "reasons": "; ".join(reasons),
                }
            )
    alerts.sort(key=lambda x: x["count"], reverse=True)
    return alerts

def alerts_text() -> str:
    alerts = compute_alerts()
    if not alerts:
        return "Тревожных студентов за последние 7 дней не выявлено."
    lines = ["ТРЕВОЖНАЯ СВОДКА патрульной службы", f"Дата: {datetime.now().strftime('%d.%m.%Y')}"]
    for a in alerts:
        lines.append(f"- {a['name']} ({a['groups']}): {a['reasons']}; типы: {a['types']}; последнее: {a['last'][:10]}.")
    return "\n".join(lines)

def admin_alerts(request: Request):
    if not M.is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    return _TPL.TemplateResponse(
        "alerts.html",
        {
            "request": request,
            "alerts": compute_alerts(),
            "emails": M.get_meta("alert_emails", ""),
            "smtp_host": os.environ.get("SMTP_HOST", ""),
            "last_send": M.get_meta("last_alert_send", "") or "никогда",
        },
    )

async def admin_alerts_emails(request: Request):
    if not M.is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    form = await request.form()
    emails = (form.get("emails") or "").strip()
    M.set_meta("alert_emails", emails)
    M.log_action(request, "смена списка почтовой рассылки", emails[:200])
    return M.toast_redirect("/admin/alerts", "Список адресов сохранён")

def admin_memo(
    request: Request,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    department: Optional[str] = None,
):
    if not M.is_admin(request):
        return RedirectResponse(url="/login", status_code=303)
    now = datetime.now()
    if not date_from:
        date_from = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    if not date_to:
        date_to = now.strftime("%Y-%m-%d")
    departments = M.get_departments()
    query = "SELECT * FROM violations WHERE deleted_at IS NULL AND created_at >= ? AND created_at <= ?"
    params = [date_from + " 00:00:00", date_to + " 23:59:59"]
    if department:
        query += " AND student_group LIKE ?"
        params.append(f"{department}%")
    query += " ORDER BY created_at DESC"
    conn = M.get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    by_type = Counter(r["violation_type"] for r in rows)
    by_student = Counter(r["student_name"] for r in rows)
    org = M.get_meta("org_name", "") or "Учебное заведение"
    return _TPL.TemplateResponse(
        "memo.html",
        {
            "request": request,
            "org": org,
            "period_start": date_from,
            "period_end": date_to,
            "generated": now.strftime("%d.%m.%Y"),
            "total": len(rows),
            "by_type": by_type.most_common(),
            "top_students": by_student.most_common(5),
            "dept_name": departments.get(department or "", ""),
        },
    )

# ---------------------------------------------------------------------------
# Почтовая рассылка тревожной сводки (если настроен SMTP)
# ---------------------------------------------------------------------------
def send_alert_email(text: str) -> bool:
    host = os.environ.get("SMTP_HOST")
    recipients = [e.strip() for e in M.get_meta("alert_emails", "").split(",") if e.strip()]
    if not host or not recipients:
        return False
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
        msg = EmailMessage()
        msg["Subject"] = "Тревожная сводка патрульной службы"
        msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "patrol@college.local"))
        msg["To"] = ", ".join(recipients)
        msg.set_content(text)
        with smtplib.SMTP(host, port, timeout=30) as server:
            if os.environ.get("SMTP_TLS", "1") == "1":
                server.starttls()
            user = os.environ.get("SMTP_USER")
            password = os.environ.get("SMTP_PASS")
            if user and password:
                server.login(user, password)
            server.send_message(msg)
        return True
    except Exception as e:
        M.log_error("devext", f"ошибка отправки почты: {e!r}")
        return False

def scheduler_loop():
    while True:
        try:
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            if now.hour == 8 and M.get_meta("last_alert_send", "") != today:
                text = alerts_text()
                if send_alert_email(text):
                    M.set_meta("last_alert_send", today)
                    print("DEVEXT: тревожная сводка отправлена", flush=True)
        except Exception:
            pass
        time.sleep(600)

# ---------------------------------------------------------------------------
# Регистрация маршрутов и слоёв
# ---------------------------------------------------------------------------
def register(app, templates):
    global _TPL
    _TPL = templates

    app.middleware("http")(maintenance_mw)
    app.middleware("http")(access_log_mw)

    app.get("/dev/health")(dev_health)
    app.get("/dev/monitor", response_class=HTMLResponse)(dev_monitor)
    app.get("/dev/selftest", response_class=HTMLResponse)(dev_selftest)
    app.get("/dev/controls", response_class=HTMLResponse)(dev_controls)
    app.post("/dev/controls/maintenance")(dev_controls_maintenance)
    app.post("/dev/controls/flags")(dev_controls_flags_post)
    app.get("/admin/alerts", response_class=HTMLResponse)(admin_alerts)
    app.post("/admin/alerts/emails")(admin_alerts_emails)
    app.get("/admin/memo", response_class=HTMLResponse)(admin_memo)

    threading.Thread(target=scheduler_loop, daemon=True).start()
    print("DEVEXT: служебные расширения зарегистрированы", flush=True)
