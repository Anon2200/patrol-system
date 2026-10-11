# ---------------------------------------------------------------------------
# Бот мессенджера MAX: одноразовая привязка аккаунта и пошаговый мастер
# записи нарушений. Служебные команды для администраторов и разработчика.
# Запускается только при заданной переменной окружения MAX_BOT_TOKEN.
# ---------------------------------------------------------------------------
import json
import os
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

# Если MAX отвечает 404 на какой-то метод — сверьте пути с официальной
# документацией Bot API MAX и поправьте ТОЛЬКО этот блок:
MAX_BOT_TOKEN = os.environ.get("MAX_BOT_TOKEN", "")
API_BASE = os.environ.get("MAX_API_BASE", "https://botapi.max.ru")
METHODS = {
    "updates": "updates",
    "send": "messages/sendMessage",
}
POLL_TIMEOUT = 25

BASE_DIR = Path(__file__).resolve().parent
DB_DIR = Path(os.environ.get("DB_DIR", str(BASE_DIR)))
DB_PATH = DB_DIR / "patrol.db"

DEFAULT_TYPES = [
    "Опоздание",
    "Нарушение лок. акта №36",
    "Нарушение дисциплины",
    "Курение в неположенном месте",
    "Другое",
]

_STATES = {}
_marker = None

# ---------------------------------------------------------------------------
# База и справочники (модуль автономный)
# ---------------------------------------------------------------------------
def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_table() -> None:
    conn = get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS max_links (
            user_id TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            patrol_name TEXT,
            linked_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()

def get_meta(key: str, default: str = "") -> str:
    conn = get_conn()
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row and row["value"] is not None else default

def set_meta(key: str, value: str) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()

def get_pin() -> str:
    return get_meta("patrol_pin") or os.environ.get("PATROL_PIN", "1234")

def get_admin_password() -> str:
    return get_meta("admin_password") or os.environ.get("ADMIN_PASSWORD", "1029384756")

def get_dev_password() -> str:
    return get_meta("dev_password") or os.environ.get("DEV_PASSWORD", "developer")

def get_types():
    raw = get_meta("violation_types")
    if raw:
        try:
            lst = json.loads(raw)
            if isinstance(lst, list) and lst:
                return lst
        except ValueError:
            pass
    return list(DEFAULT_TYPES)

def known_students():
    conn = get_conn()
    rows = conn.execute(
        "SELECT student_name, student_group FROM violations WHERE deleted_at IS NULL ORDER BY id DESC"
    ).fetchall()
    conn.close()
    known = {}
    for row in rows:
        known.setdefault(row["student_name"], row["student_group"])
    return known

def member_names():
    conn = get_conn()
    rows = conn.execute("SELECT name FROM patrol_members ORDER BY id").fetchall()
    conn.close()
    return [r["name"] for r in rows]

def log_action(actor: str, role: str, action: str, details: str = "") -> None:
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO audit_log (created_at, actor, role, action, details) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), actor, role, action, details[:500]),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Сеть MAX
# ---------------------------------------------------------------------------
def _request(path: str, payload=None, params=None):
    url = API_BASE + "/" + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("Authorization", "Bearer " + MAX_BOT_TOKEN)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=POLL_TIMEOUT + 10) as resp:
        return json.loads(resp.read().decode())

def send(chat_id, text: str) -> None:
    try:
        _request(METHODS["send"], {"chat_id": chat_id, "text": text})
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Привязки аккаунтов MAX к ролям
# ---------------------------------------------------------------------------
def get_link(user_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM max_links WHERE user_id = ?", (str(user_id),)).fetchone()
    conn.close()
    return row

def set_link(user_id: str, role: str, patrol_name: str) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO max_links (user_id, role, patrol_name, linked_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET role = excluded.role, patrol_name = excluded.patrol_name, linked_at = excluded.linked_at",
        (str(user_id), role, patrol_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()

def del_link(user_id: str) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM max_links WHERE user_id = ?", (str(user_id),))
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# Записи нарушений
# ---------------------------------------------------------------------------
def insert_violation(patrol_name: str, student: str, group: str, vtype: str, comment: str) -> int:
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO violations
            (patrol_name, student_name, student_group, violation_type, comment, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (patrol_name, student, group, vtype, comment, created_at),
    )
    conn.commit()
    vid = cur.lastrowid
    conn.close()
    return vid

def today_duplicate(student: str, vtype: str) -> bool:
    today = datetime.now().strftime("%Y-%m-%d")
    conn = get_conn()
    row = conn.execute(
        "SELECT id FROM violations WHERE deleted_at IS NULL AND lower(student_name) = lower(?) AND violation_type = ? AND created_at >= ?",
        (student, vtype, today + " 00:00:00"),
    ).fetchone()
    conn.close()
    return bool(row)

# ---------------------------------------------------------------------------
# Служебные тексты администраторов
# ---------------------------------------------------------------------------
def report_text(kind: str, extra: str = "") -> str:
    conn = get_conn()
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    if kind == "today":
        rows = conn.execute("SELECT * FROM violations WHERE deleted_at IS NULL AND created_at >= ? ORDER BY created_at DESC", (today + " 00:00:00",)).fetchall()
        head = f"Сегодня нарушений: {len(rows)}"
    elif kind == "week":
        rows = conn.execute("SELECT * FROM violations WHERE deleted_at IS NULL AND created_at >= ? ORDER BY created_at DESC", (week_ago + " 00:00:00",)).fetchall()
        head = f"За 7 дней нарушений: {len(rows)}"
    elif kind == "last":
        rows = conn.execute("SELECT * FROM violations WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 5").fetchall()
        head = "Последние 5 записей:"
    else:
        like = f"%{extra}%"
        rows = conn.execute(
            "SELECT * FROM violations WHERE deleted_at IS NULL AND (student_name LIKE ? OR student_group LIKE ? OR comment LIKE ?) ORDER BY created_at DESC LIMIT 5",
            (like, like, like),
        ).fetchall()
        head = f"Поиск «{extra}», показаны 5:"
    conn.close()
    lines = [head]
    for r in rows:
        lines.append(f"• {r['created_at'][5:16]} {r['student_name']} ({r['student_group']}) — {r['violation_type']}")
    return "\n".join(lines)

def deviants_text() -> str:
    try:
        min_count = max(1, int(get_meta("deviant_min", "2")))
    except ValueError:
        min_count = 2
    conn = get_conn()
    rows = conn.execute(
        "SELECT student_name, COUNT(*) AS c FROM violations WHERE deleted_at IS NULL GROUP BY student_name HAVING COUNT(*) >= ? ORDER BY c DESC LIMIT 7",
        (min_count,),
    ).fetchall()
    conn.close()
    if not rows:
        return "Девиантов не выявлено."
    lines = [f"Девианты (порог {min_count}+):"]
    for r in rows:
        lines.append(f"• {r['student_name']} — {r['c']}")
    return "\n".join(lines)

def system_text() -> str:
    conn = get_conn()
    v = conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NULL").fetchone()[0]
    t = conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NULL AND created_at >= ?", (datetime.now().strftime("%Y-%m-%d") + " 00:00:00",)).fetchone()[0]
    tr = conn.execute("SELECT COUNT(*) FROM violations WHERE deleted_at IS NOT NULL").fetchone()[0]
    conn.close()
    return f"Система: записей в базе {v}, за сегодня {t}, в корзине {tr}."

def menu_text(link) -> str:
    if link["role"] == "patrol":
        return (
            f"Вы вошли как {link['patrol_name']}.\n"
            "записать — новая запись нарушения (мастер проведёт по шагам)\n"
            "/start — меню и помощь\n"
            "/unlink — отвязать аккаунт"
        )
    role_label = "разработчик" if link["role"] == "dev" else "администратор"
    lines = [
        f"Роль: {role_label}.",
        "Команды: /today /week /deviants /last /search текст",
        "записать — мастер записи нарушения",
    ]
    if link["role"] == "dev":
        lines.append("/system — показатели системы")
    lines.append("/unlink — отвязать аккаунт")
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Состояния мастера
# ---------------------------------------------------------------------------
def set_state(user_id: str, step: str, data=None) -> None:
    _STATES[str(user_id)] = {"step": step, "data": data or {}}

def get_state(user_id: str):
    return _STATES.get(str(user_id))

def clear_state(user_id: str) -> None:
    _STATES.pop(str(user_id), None)

def finalize(chat_id, user_id, data, force: bool) -> None:
    if not force and today_duplicate(data["student"], data["type"]):
        set_state(user_id, "DUP_CONFIRM", data)
        send(chat_id, f"Сегодня уже записано «{data['type']}» для студента {data['student']}. Записать ещё раз? Ответьте да или отмена.")
        return
    link = get_link(user_id)
    patrol = (link["patrol_name"] if link else "") or "патруль"
    vid = insert_violation(patrol, data["student"], data["group"], data["type"], data["comment"])
    log_action(patrol, "patrol", "нарушение через MAX", f"#{vid} {data['student']} {data['group']} {data['type']}")
    clear_state(user_id)
    send(
        chat_id,
        f"Записано: #{vid}\nСтудент: {data['student']}\nГруппа: {data['group']}\nТип: {data['type']}\nКомментарий: {data['comment'] or '—'}\n\nНовое нарушение — отправьте: записать",
    )

# ---------------------------------------------------------------------------
# Обработка входящих сообщений
# ---------------------------------------------------------------------------
def handle_update(update: dict) -> None:
    msg = update.get("message") or update.get("message_created") or {}
    if not isinstance(msg, dict):
        return
    text = (msg.get("text") or "").strip()
    chat_id = msg.get("chat_id") or (msg.get("chat") or {}).get("id")
    user_id = str((msg.get("from") or {}).get("user_id") or msg.get("user_id") or "")
    if not text or chat_id is None or not user_id:
        return

    low = text.lower()
    link = get_link(user_id)
    state = get_state(user_id)

    if low in ("/start", "/help", "старт", "помощь"):
        clear_state(user_id)
        if not link:
            set_state(user_id, "LINK_NAME")
            send(chat_id, "Бот патрульной службы.\nПривязка, шаг 1 из 2: введите свою фамилию, как в составе патруля.")
        else:
            send(chat_id, menu_text(link))
        return

    if low == "/unlink":
        del_link(user_id)
        clear_state(user_id)
        send(chat_id, "Аккаунт отвязан. Для новой привязки отправьте /start.")
        return

    parts = text.split()
    if parts and parts[0].lower() == "link-admin":
        if len(parts) >= 2 and parts[1] == get_admin_password():
            set_link(user_id, "admin", "админ")
            log_action("админ", "admin", "привязка аккаунта MAX")
            send(chat_id, "Привязано: администратор.\n" + menu_text(get_link(user_id)))
        else:
            send(chat_id, "Неверный пароль администратора.")
        return
    if parts and parts[0].lower() == "link-dev":
        if len(parts) >= 2 and parts[1] == get_dev_password():
            set_link(user_id, "dev", "разработчик")
            log_action("разработчик", "dev", "привязка аккаунта MAX")
            send(chat_id, "Привязано: разработчик.\n" + menu_text(get_link(user_id)))
        else:
            send(chat_id, "Неверный пароль разработчика.")
        return

    # ----- мастер привязки патрульного -----
    if not link:
        if state and state["step"] == "LINK_NAME":
            name = text.strip()
            if name in member_names():
                set_state(user_id, "LINK_PIN", {"name": name})
                send(chat_id, f"Фамилия принята: {name}.\nШаг 2 из 2: введите ПИН-код.")
            else:
                send(chat_id, "Такой фамилии нет в составе патруля. Введите фамилию точно как в списке.")
            return
        if state and state["step"] == "LINK_PIN":
            name = state["data"].get("name", "")
            if text.strip() == get_pin():
                set_link(user_id, "patrol", name)
                clear_state(user_id)
                log_action(name, "patrol", "привязка аккаунта MAX")
                send(chat_id, f"Привязка завершена: {name}.\nДля записи нарушения отправьте: записать")
            else:
                send(chat_id, "Неверный ПИН. Введите ПИН ещё раз.")
            return
        send(chat_id, "Аккаунт не привязан. Отправьте /start и выполните два шага привязки.")
        return

    role = link["role"]

    # ----- служебные команды админа и разработчика -----
    if role in ("admin", "dev"):
        if low == "/today":
            send(chat_id, report_text("today"))
            return
        if low == "/week":
            send(chat_id, report_text("week"))
            return
        if low == "/deviants":
            send(chat_id, deviants_text())
            return
        if low == "/last":
            send(chat_id, report_text("last"))
            return
        if low.startswith("/search"):
            send(chat_id, report_text("search", text[7:].strip()))
            return
        if low == "/system" and role == "dev":
            send(chat_id, system_text())
            return

    # ----- запуск мастера записи -----
    if low in ("записать", "/new", "new"):
        set_state(user_id, "W_STUDENT")
        send(chat_id, "Шаг 1 из 4: введите фамилию и имя студента-нарушителя.")
        return

    # ----- шаги мастера записи -----
    if state:
        step = state["step"]
        data = state["data"]
        if step == "W_STUDENT":
            data["student"] = text.strip()
            hint = known_students().get(data["student"], "")
            set_state(user_id, "W_GROUP", data)
            message = "Шаг 2 из 4: введите группу студента."
            if hint:
                message += f"\nПодсказка: в базе этого студента есть группа {hint} — отправьте её или введите другую."
            send(chat_id, message)
            return
        if step == "W_GROUP":
            data["group"] = text.strip().upper()
            types = get_types()
            data["types"] = types
            listing = "\n".join(f"{i + 1}. {t}" for i, t in enumerate(types))
            set_state(user_id, "W_TYPE", data)
            send(chat_id, f"Шаг 3 из 4: выберите тип нарушения, отправьте номер:\n{listing}")
            return
        if step == "W_TYPE":
            types = data.get("types") or get_types()
            choice = None
            if text.isdigit() and 1 <= int(text) <= len(types):
                choice = types[int(text) - 1]
            else:
                for t in types:
                    if t.casefold() == low or t.casefold() in low:
                        choice = t
                        break
            if not choice:
                send(chat_id, "Отправьте номер типа из списка или его название.")
                return
            data["type"] = choice
            set_state(user_id, "W_COMMENT", data)
            send(chat_id, "Шаг 4 из 4: напишите комментарий. Если не нужен — отправьте: пропустить")
            return
        if step == "W_COMMENT":
            data["comment"] = "" if low in ("пропустить", "нет", "-") else text.strip()
            set_state(user_id, "W_CONFIRM", data)
            send(
                chat_id,
                "Проверьте запись:\n"
                f"Студент: {data['student']}\n"
                f"Группа: {data['group']}\n"
                f"Тип: {data['type']}\n"
                f"Комментарий: {data['comment'] or '—'}\n"
                "Отправьте да для записи или отмена для отмены.",
            )
            return
        if step == "W_CONFIRM":
            if low in ("отмена", "нет", "отменить"):
                clear_state(user_id)
                send(chat_id, "Запись отменена.")
                return
            if low in ("да", "подтвердить", "ок", "записать"):
                finalize(chat_id, user_id, data, force=False)
                return
            send(chat_id, "Отправьте да или отмена.")
            return
        if step == "DUP_CONFIRM":
            if low in ("да", "подтвердить"):
                finalize(chat_id, user_id, data, force=True)
            else:
                clear_state(user_id)
                send(chat_id, "Запись отменена.")
            return

    send(chat_id, menu_text(link))

# ---------------------------------------------------------------------------
# Опрос очереди сообщений MAX
# ---------------------------------------------------------------------------
def poll_loop() -> None:
    global _marker
    if _marker is None:
        try:
            _marker = int(get_meta("max_marker", "0") or 0)
        except ValueError:
            _marker = 0
    while True:
        try:
            data = _request(METHODS["updates"], params={"marker": _marker, "timeout": POLL_TIMEOUT})
            for u in data.get("updates", []) or []:
                handle_update(u)
            new_marker = data.get("marker")
            if new_marker is not None:
                _marker = int(new_marker)
                set_meta("max_marker", str(_marker))
        except Exception:
            time.sleep(5)

def start_polling() -> None:
    if not MAX_BOT_TOKEN:
        return
    ensure_table()
    threading.Thread(target=poll_loop, daemon=True).start()

start_polling()
