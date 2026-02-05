"""
FlowCast Planner — Python (Flask + SQLite + Auth)
Cada usuário tem login/senha e seus próprios canais, prompts e tarefas.
Pronto para deploy no Railway.
"""

import os
import json
import sqlite3
import uuid
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify, g,
    session, redirect, url_for
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "flowcast.db"))

# ───────────────────────────── DATABASE ─────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            email       TEXT NOT NULL UNIQUE,
            password    TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS channels (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            name        TEXT NOT NULL,
            icon        TEXT NOT NULL DEFAULT '📺',
            color       TEXT NOT NULL DEFAULT '#2563eb',
            frequency   TEXT NOT NULL DEFAULT '1x_dia',
            times       TEXT NOT NULL DEFAULT '["08:00"]',
            first_day_on TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS prompts (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            channel_id  TEXT NOT NULL,
            name        TEXT NOT NULL,
            category    TEXT DEFAULT '',
            content     TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS completed_tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT NOT NULL,
            task_key    TEXT NOT NULL,
            completed_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, task_key)
        );
        CREATE TABLE IF NOT EXISTS contents (
            id           TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL,
            channel_id   TEXT NOT NULL,
            title        TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pendente',
            published_at TEXT,
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
        );
    """)
    db.commit()
    db.close()


# ──────────────────────── PASSWORD HASHING ──────────────────────────

def hash_password(password):
    """Hash password with salt using SHA-256 (no extra deps needed)."""
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return salt + ":" + h.hex()


def check_password(stored, password):
    """Verify password against stored hash."""
    try:
        salt, hashed = stored.split(":", 1)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(h.hex(), hashed)
    except Exception:
        return False


# ──────────────────────────── HELPERS ───────────────────────────────

def new_id():
    return uuid.uuid4().hex[:12]


def row_to_dict(row):
    return dict(row) if row else None


def rows_to_list(rows):
    return [dict(r) for r in rows]


def current_user_id():
    return session.get("user_id")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


FREQ_LABELS = {
    "1x_dia": "1x por dia",
    "2x_dia": "2x por dia",
    "3x_dia": "3x por dia",
    "dia_sim_nao": "Dia sim, dia não",
    "dia_sim_nao_2x": "Dia sim, dia não (2x)",
    "terca_quinta": "Terça e Quinta",
}

WEEKDAYS_PT = ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"]


def get_date_range(period):
    today = datetime.now().date()
    if period == "tomorrow":
        d = today + timedelta(days=1)
        return d, d
    elif period == "week":
        return today, today + timedelta(days=6)
    elif period == "next-week":
        return today + timedelta(days=7), today + timedelta(days=13)
    elif period == "15days":
        return today, today + timedelta(days=14)
    return today, today


def should_post(channel, date_obj):
    freq = channel["frequency"]
    if freq in ("1x_dia", "2x_dia", "3x_dia"):
        return True
    if freq == "terca_quinta":
        return date_obj.weekday() in (1, 3)
    if freq.startswith("dia_sim_nao"):
        first_str = channel.get("first_day_on") or datetime.now().strftime("%Y-%m-%d")
        try:
            first = datetime.strptime(first_str, "%Y-%m-%d").date()
        except ValueError:
            first = datetime.now().date()
        return (date_obj - first).days % 2 == 0
    return True


def get_times_for_channel(channel):
    try:
        times = json.loads(channel["times"])
    except (json.JSONDecodeError, TypeError):
        times = ["08:00"]
    freq = channel["frequency"]
    if freq in ("2x_dia", "dia_sim_nao_2x"):
        while len(times) < 2:
            times.append("14:00")
        return times[:2]
    if freq == "3x_dia":
        while len(times) < 3:
            times.append("12:00" if len(times) == 1 else "18:00")
        return times[:3]
    return [times[0]] if times else ["08:00"]


def generate_tasks(user_id, period="today", filter_channel=None):
    db = get_db()
    channels = rows_to_list(
        db.execute("SELECT * FROM channels WHERE user_id = ?", (user_id,)).fetchall()
    )
    completed = {
        r["task_key"]
        for r in db.execute(
            "SELECT task_key FROM completed_tasks WHERE user_id = ?", (user_id,)
        ).fetchall()
    }
    start_date, end_date = get_date_range(period)
    tasks = []
    current = start_date
    while current <= end_date:
        for ch in channels:
            if filter_channel and ch["id"] != filter_channel:
                continue
            if should_post(ch, current):
                for t in get_times_for_channel(ch):
                    key = f"{ch['id']}_{current.isoformat()}_{t}"
                    tasks.append({
                        "key": key,
                        "channel_id": ch["id"],
                        "channel_name": ch["name"],
                        "channel_icon": ch["icon"],
                        "channel_color": ch["color"],
                        "date": current.isoformat(),
                        "date_formatted": f"{current.strftime('%d/%m')} ({WEEKDAYS_PT[current.weekday()]})",
                        "time": t,
                        "done": key in completed,
                    })
        current += timedelta(days=1)
    tasks.sort(key=lambda x: (x["date"], x["time"]))
    return tasks


# ──────────────────────── AUTH ROUTES ───────────────────────────────

@app.route("/login")
def login_page():
    if session.get("user_id"):
        return redirect("/")
    return render_template("login.html")


@app.route("/register")
def register_page():
    if session.get("user_id"):
        return redirect("/")
    return render_template("register.html")


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data = request.json
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name or not email or not password:
        return jsonify({"error": "Preencha todos os campos"}), 400
    if len(password) < 6:
        return jsonify({"error": "A senha deve ter pelo menos 6 caracteres"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return jsonify({"error": "Este e-mail já está cadastrado"}), 400

    user_id = new_id()
    db.execute(
        "INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)",
        (user_id, name, email, hash_password(password)),
    )
    db.commit()
    session["user_id"] = user_id
    session["user_name"] = name
    session["user_email"] = email
    return jsonify({"ok": True})


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.json
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Preencha todos os campos"}), 400

    db = get_db()
    user = row_to_dict(
        db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    )
    if not user or not check_password(user["password"], password):
        return jsonify({"error": "E-mail ou senha incorretos"}), 401

    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    return jsonify({"ok": True})


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/auth/me")
@login_required
def api_me():
    return jsonify({
        "id": session["user_id"],
        "name": session.get("user_name", ""),
        "email": session.get("user_email", ""),
    })


# ──────────────────────── MAIN ROUTES ──────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        user_name=session.get("user_name", ""),
        user_email=session.get("user_email", ""),
    )


# ── API: Tasks ──

@app.route("/api/tasks")
@login_required
def api_tasks():
    uid = current_user_id()
    period = request.args.get("period", "today")
    channel = request.args.get("channel", "")
    tasks = generate_tasks(uid, period, channel or None)
    total = len(tasks)
    done = sum(1 for t in tasks if t["done"])
    pct = round(done / total * 100) if total else 0
    grouped = {}
    for t in tasks:
        grouped.setdefault(t["date"], {"label": t["date_formatted"], "tasks": []})
        grouped[t["date"]]["tasks"].append(t)
    return jsonify({
        "groups": [grouped[d] for d in sorted(grouped)],
        "total": total, "done": done, "pct": pct,
    })


@app.route("/api/tasks/toggle", methods=["POST"])
@login_required
def api_toggle_task():
    uid = current_user_id()
    key = request.json.get("key")
    if not key:
        return jsonify({"error": "key required"}), 400
    db = get_db()
    existing = db.execute(
        "SELECT id FROM completed_tasks WHERE user_id = ? AND task_key = ?",
        (uid, key),
    ).fetchone()
    if existing:
        db.execute("DELETE FROM completed_tasks WHERE user_id = ? AND task_key = ?", (uid, key))
    else:
        db.execute("INSERT INTO completed_tasks (user_id, task_key) VALUES (?, ?)", (uid, key))
    db.commit()
    return jsonify({"toggled": True, "done": not bool(existing)})


@app.route("/api/stats")
@login_required
def api_stats():
    uid = current_user_id()
    db = get_db()
    ch_count = db.execute("SELECT COUNT(*) c FROM channels WHERE user_id = ?", (uid,)).fetchone()["c"]
    today_tasks = generate_tasks(uid, "today")
    week_tasks = generate_tasks(uid, "week")
    return jsonify({"channels": ch_count, "today": len(today_tasks), "week": len(week_tasks)})


# ── API: Channels ──

@app.route("/api/channels")
@login_required
def api_channels():
    uid = current_user_id()
    db = get_db()
    channels = rows_to_list(
        db.execute("SELECT * FROM channels WHERE user_id = ? ORDER BY created_at", (uid,)).fetchall()
    )
    for ch in channels:
        ch["times"] = json.loads(ch["times"])
        ch["freq_label"] = FREQ_LABELS.get(ch["frequency"], ch["frequency"])
        ch["prompt_count"] = db.execute(
            "SELECT COUNT(*) c FROM prompts WHERE channel_id = ? AND user_id = ?",
            (ch["id"], uid),
        ).fetchone()["c"]
        ch["content_count"] = db.execute(
            "SELECT COUNT(*) c FROM contents WHERE channel_id = ? AND user_id = ?",
            (ch["id"], uid),
        ).fetchone()["c"]
        ch["content_pending"] = db.execute(
            "SELECT COUNT(*) c FROM contents WHERE channel_id = ? AND user_id = ? AND status = 'pendente'",
            (ch["id"], uid),
        ).fetchone()["c"]
    return jsonify(channels)


@app.route("/api/channels", methods=["POST"])
@login_required
def api_create_channel():
    uid = current_user_id()
    data = request.json
    ch_id = new_id()
    db = get_db()
    db.execute(
        """INSERT INTO channels (id, user_id, name, icon, color, frequency, times, first_day_on)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (ch_id, uid, data["name"], data.get("icon", "📺"), data.get("color", "#2563eb"),
         data.get("frequency", "1x_dia"), json.dumps(data.get("times", ["08:00"])),
         data.get("first_day_on") or None),
    )
    db.commit()
    return jsonify({"id": ch_id, "ok": True})


@app.route("/api/channels/<ch_id>", methods=["PUT"])
@login_required
def api_update_channel(ch_id):
    uid = current_user_id()
    data = request.json
    db = get_db()
    db.execute(
        """UPDATE channels SET name=?, icon=?, color=?, frequency=?, times=?, first_day_on=?
           WHERE id=? AND user_id=?""",
        (data["name"], data.get("icon", "📺"), data.get("color", "#2563eb"),
         data.get("frequency", "1x_dia"), json.dumps(data.get("times", ["08:00"])),
         data.get("first_day_on") or None, ch_id, uid),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/channels/<ch_id>", methods=["DELETE"])
@login_required
def api_delete_channel(ch_id):
    uid = current_user_id()
    db = get_db()
    db.execute("DELETE FROM channels WHERE id = ? AND user_id = ?", (ch_id, uid))
    db.commit()
    return jsonify({"ok": True})


# ── API: Prompts ──

@app.route("/api/prompts/<channel_id>")
@login_required
def api_prompts(channel_id):
    uid = current_user_id()
    db = get_db()
    prompts = rows_to_list(
        db.execute(
            "SELECT * FROM prompts WHERE channel_id = ? AND user_id = ? ORDER BY created_at",
            (channel_id, uid),
        ).fetchall()
    )
    return jsonify(prompts)


@app.route("/api/prompts", methods=["POST"])
@login_required
def api_create_prompt():
    uid = current_user_id()
    data = request.json
    pr_id = new_id()
    db = get_db()
    db.execute(
        """INSERT INTO prompts (id, user_id, channel_id, name, category, content)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (pr_id, uid, data["channel_id"], data["name"],
         data.get("category", ""), data.get("content", "")),
    )
    db.commit()
    return jsonify({"id": pr_id, "ok": True})


@app.route("/api/prompts/<pr_id>", methods=["PUT"])
@login_required
def api_update_prompt(pr_id):
    uid = current_user_id()
    data = request.json
    db = get_db()
    db.execute(
        "UPDATE prompts SET name=?, category=?, content=? WHERE id=? AND user_id=?",
        (data["name"], data.get("category", ""), data.get("content", ""), pr_id, uid),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/prompts/<pr_id>", methods=["DELETE"])
@login_required
def api_delete_prompt(pr_id):
    uid = current_user_id()
    db = get_db()
    db.execute("DELETE FROM prompts WHERE id = ? AND user_id = ?", (pr_id, uid))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/prompts/<pr_id>/detail")
@login_required
def api_prompt_detail(pr_id):
    uid = current_user_id()
    db = get_db()
    pr = row_to_dict(
        db.execute("SELECT * FROM prompts WHERE id = ? AND user_id = ?", (pr_id, uid)).fetchone()
    )
    if not pr:
        return jsonify({"error": "not found"}), 404
    return jsonify(pr)


# ── API: Contents ──

@app.route("/api/contents/<channel_id>")
@login_required
def api_contents(channel_id):
    uid = current_user_id()
    db = get_db()
    status_filter = request.args.get("status", "")
    if status_filter:
        contents = rows_to_list(
            db.execute(
                "SELECT * FROM contents WHERE channel_id = ? AND user_id = ? AND status = ? ORDER BY created_at DESC",
                (channel_id, uid, status_filter),
            ).fetchall()
        )
    else:
        contents = rows_to_list(
            db.execute(
                "SELECT * FROM contents WHERE channel_id = ? AND user_id = ? ORDER BY CASE status WHEN 'pendente' THEN 0 WHEN 'publicado' THEN 1 END, created_at DESC",
                (channel_id, uid),
            ).fetchall()
        )
    return jsonify(contents)


@app.route("/api/contents", methods=["POST"])
@login_required
def api_create_content():
    uid = current_user_id()
    data = request.json
    ct_id = new_id()
    db = get_db()
    db.execute(
        """INSERT INTO contents (id, user_id, channel_id, title, status, published_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (ct_id, uid, data["channel_id"], data["title"],
         data.get("status", "pendente"), data.get("published_at") or None),
    )
    db.commit()
    return jsonify({"id": ct_id, "ok": True})


@app.route("/api/contents/<ct_id>", methods=["PUT"])
@login_required
def api_update_content(ct_id):
    uid = current_user_id()
    data = request.json
    db = get_db()
    db.execute(
        "UPDATE contents SET title=?, status=?, published_at=? WHERE id=? AND user_id=?",
        (data["title"], data.get("status", "pendente"),
         data.get("published_at") or None, ct_id, uid),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/contents/<ct_id>/toggle", methods=["POST"])
@login_required
def api_toggle_content(ct_id):
    uid = current_user_id()
    db = get_db()
    ct = row_to_dict(
        db.execute("SELECT * FROM contents WHERE id = ? AND user_id = ?", (ct_id, uid)).fetchone()
    )
    if not ct:
        return jsonify({"error": "not found"}), 404
    if ct["status"] == "pendente":
        new_status = "publicado"
        pub_date = datetime.now().strftime("%Y-%m-%d")
    else:
        new_status = "pendente"
        pub_date = None
    db.execute(
        "UPDATE contents SET status=?, published_at=? WHERE id=? AND user_id=?",
        (new_status, pub_date, ct_id, uid),
    )
    db.commit()
    return jsonify({"ok": True, "status": new_status, "published_at": pub_date})


@app.route("/api/contents/<ct_id>", methods=["DELETE"])
@login_required
def api_delete_content(ct_id):
    uid = current_user_id()
    db = get_db()
    db.execute("DELETE FROM contents WHERE id = ? AND user_id = ?", (ct_id, uid))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/contents-stats")
@login_required
def api_contents_stats():
    uid = current_user_id()
    db = get_db()
    total = db.execute("SELECT COUNT(*) c FROM contents WHERE user_id = ?", (uid,)).fetchone()["c"]
    published = db.execute("SELECT COUNT(*) c FROM contents WHERE user_id = ? AND status = 'publicado'", (uid,)).fetchone()["c"]
    pending = total - published
    return jsonify({"total": total, "published": published, "pending": pending})


# ────────────────────────────── MAIN ────────────────────────────────

# Sempre inicializa o banco (funciona tanto com gunicorn quanto direto)
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  ⚡ FlowCast Planner rodando em http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
