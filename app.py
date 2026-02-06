"""
FlowCast Planner — Python (Flask + PostgreSQL + Auth)
Cada usuário tem login/senha e seus próprios canais, prompts e tarefas.
Dados persistem entre deploys via PostgreSQL.
"""

import os
import json
import uuid
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify, g,
    session, redirect, url_for, send_file
)
import psycopg2
from psycopg2.extras import RealDictCursor
import base64
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload

DATABASE_URL = os.environ.get("DATABASE_URL", "")

# ───────────────────────────── DATABASE ─────────────────────────────

def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        g.db.autocommit = False
    return g.db


def db_execute(query, params=None):
    db = get_db()
    cur = db.cursor()
    cur.execute(query, params or ())
    return cur


def db_fetchone(query, params=None):
    cur = db_execute(query, params)
    row = cur.fetchone()
    cur.close()
    return dict(row) if row else None


def db_fetchall(query, params=None):
    cur = db_execute(query, params)
    rows = cur.fetchall()
    cur.close()
    return [dict(r) for r in rows]


def db_commit():
    get_db().commit()


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        try:
            if exc:
                db.rollback()
            db.close()
        except Exception:
            pass


def init_db():
    if not DATABASE_URL:
        print("⚠️  DATABASE_URL não configurada.")
        return
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS channels (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL, icon TEXT NOT NULL DEFAULT '📺', color TEXT NOT NULL DEFAULT '#2563eb',
            frequency TEXT NOT NULL DEFAULT '1x_dia', times TEXT NOT NULL DEFAULT '["08:00"]',
            first_day_on TEXT, created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS prompts (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            name TEXT NOT NULL, category TEXT DEFAULT '', content TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS completed_tasks (
            id SERIAL PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            task_key TEXT NOT NULL, completed_at TIMESTAMP NOT NULL DEFAULT NOW(),
            UNIQUE(user_id, task_key)
        )""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS contents (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pendente',
            published_at TEXT, thumbnail TEXT, created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS achievements (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            channel_id TEXT REFERENCES channels(id) ON DELETE SET NULL,
            title TEXT NOT NULL, description TEXT, achieved_at TEXT,
            image TEXT, created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )""")
    # Add thumbnail column if table already exists without it
    try:
        cur.execute("ALTER TABLE contents ADD COLUMN IF NOT EXISTS thumbnail TEXT")
    except Exception:
        pass
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Banco de dados inicializado")


# ──────────────────────── PASSWORD HASHING ──────────────────────────

def hash_password(password):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return salt + ":" + h.hex()

def check_password(stored, password):
    try:
        salt, hashed = stored.split(":", 1)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(h.hex(), hashed)
    except Exception:
        return False


# ──────────────────────────── HELPERS ───────────────────────────────

def new_id():
    return uuid.uuid4().hex[:12]

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

def fix_dt(obj):
    """Convert datetime fields to string for JSON."""
    if "created_at" in obj and not isinstance(obj["created_at"], str):
        obj["created_at"] = str(obj["created_at"])
    return obj

FREQ_LABELS = {
    "1x_dia": "1x por dia", "2x_dia": "2x por dia", "3x_dia": "3x por dia",
    "dia_sim_nao": "Dia sim, dia não", "dia_sim_nao_2x": "Dia sim, dia não (2x)",
    "terca_quinta": "Terça e Quinta",
}
WEEKDAYS_PT = ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"]

def get_date_range(period):
    today = datetime.now().date()
    if period == "tomorrow":
        d = today + timedelta(days=1); return d, d
    elif period == "week": return today, today + timedelta(days=6)
    elif period == "next-week": return today + timedelta(days=7), today + timedelta(days=13)
    elif period == "15days": return today, today + timedelta(days=14)
    return today, today

def should_post(channel, date_obj):
    freq = channel["frequency"]
    if freq in ("1x_dia", "2x_dia", "3x_dia"): return True
    if freq == "terca_quinta": return date_obj.weekday() in (1, 3)
    if freq.startswith("dia_sim_nao"):
        first_str = channel.get("first_day_on") or datetime.now().strftime("%Y-%m-%d")
        try: first = datetime.strptime(first_str, "%Y-%m-%d").date()
        except ValueError: first = datetime.now().date()
        return (date_obj - first).days % 2 == 0
    return True

def get_times_for_channel(channel):
    try: times = json.loads(channel["times"])
    except: times = ["08:00"]
    freq = channel["frequency"]
    if freq in ("2x_dia", "dia_sim_nao_2x"):
        while len(times) < 2: times.append("14:00")
        return times[:2]
    if freq == "3x_dia":
        while len(times) < 3: times.append("12:00" if len(times) == 1 else "18:00")
        return times[:3]
    return [times[0]] if times else ["08:00"]

def generate_tasks(user_id, period="today", filter_channel=None):
    channels = db_fetchall("SELECT * FROM channels WHERE user_id = %s", (user_id,))
    completed = {r["task_key"] for r in db_fetchall("SELECT task_key FROM completed_tasks WHERE user_id = %s", (user_id,))}
    start_date, end_date = get_date_range(period)
    tasks = []; current = start_date
    while current <= end_date:
        for ch in channels:
            if filter_channel and ch["id"] != filter_channel: continue
            if should_post(ch, current):
                for t in get_times_for_channel(ch):
                    key = f"{ch['id']}_{current.isoformat()}_{t}"
                    tasks.append({"key": key, "channel_id": ch["id"], "channel_name": ch["name"],
                        "channel_icon": ch["icon"], "channel_color": ch["color"],
                        "date": current.isoformat(),
                        "date_formatted": f"{current.strftime('%d/%m')} ({WEEKDAYS_PT[current.weekday()]})",
                        "time": t, "done": key in completed})
        current += timedelta(days=1)
    tasks.sort(key=lambda x: (x["date"], x["time"]))
    return tasks


# ──────────────────────── AUTH ROUTES ───────────────────────────────

@app.route("/login")
def login_page():
    if session.get("user_id"): return redirect("/")
    return render_template("login.html")

@app.route("/register")
def register_page():
    if session.get("user_id"): return redirect("/")
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
    existing = db_fetchone("SELECT id FROM users WHERE email = %s", (email,))
    if existing:
        return jsonify({"error": "Este e-mail já está cadastrado"}), 400
    user_id = new_id()
    db_execute("INSERT INTO users (id, name, email, password) VALUES (%s, %s, %s, %s)",
        (user_id, name, email, hash_password(password)))
    db_commit()
    session["user_id"] = user_id; session["user_name"] = name; session["user_email"] = email
    return jsonify({"ok": True})

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.json
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"error": "Preencha todos os campos"}), 400
    user = db_fetchone("SELECT * FROM users WHERE email = %s", (email,))
    if not user or not check_password(user["password"], password):
        return jsonify({"error": "E-mail ou senha incorretos"}), 401
    session["user_id"] = user["id"]; session["user_name"] = user["name"]; session["user_email"] = user["email"]
    return jsonify({"ok": True})

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear(); return jsonify({"ok": True})

@app.route("/api/auth/me")
@login_required
def api_me():
    return jsonify({"id": session["user_id"], "name": session.get("user_name", ""), "email": session.get("user_email", "")})


# ──────────────────────── MAIN ROUTES ──────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html", user_name=session.get("user_name", ""), user_email=session.get("user_email", ""))

# ── API: Tasks ──

@app.route("/api/tasks")
@login_required
def api_tasks():
    uid = current_user_id(); period = request.args.get("period", "today"); channel = request.args.get("channel", "")
    tasks = generate_tasks(uid, period, channel or None)
    total = len(tasks); done = sum(1 for t in tasks if t["done"]); pct = round(done / total * 100) if total else 0
    grouped = {}
    for t in tasks:
        grouped.setdefault(t["date"], {"label": t["date_formatted"], "tasks": []})
        grouped[t["date"]]["tasks"].append(t)
    return jsonify({"groups": [grouped[d] for d in sorted(grouped)], "total": total, "done": done, "pct": pct})

@app.route("/api/tasks/toggle", methods=["POST"])
@login_required
def api_toggle_task():
    uid = current_user_id(); key = request.json.get("key")
    if not key: return jsonify({"error": "key required"}), 400
    existing = db_fetchone("SELECT id FROM completed_tasks WHERE user_id = %s AND task_key = %s", (uid, key))
    if existing: db_execute("DELETE FROM completed_tasks WHERE user_id = %s AND task_key = %s", (uid, key))
    else: db_execute("INSERT INTO completed_tasks (user_id, task_key) VALUES (%s, %s)", (uid, key))
    db_commit()
    return jsonify({"toggled": True, "done": not bool(existing)})

@app.route("/api/stats")
@login_required
def api_stats():
    uid = current_user_id()
    ch_count = db_fetchone("SELECT COUNT(*) AS c FROM channels WHERE user_id = %s", (uid,))["c"]
    return jsonify({"channels": ch_count, "today": len(generate_tasks(uid, "today")), "week": len(generate_tasks(uid, "week"))})

# ── API: Channels ──

@app.route("/api/channels")
@login_required
def api_channels():
    uid = current_user_id()
    channels = db_fetchall("SELECT * FROM channels WHERE user_id = %s ORDER BY created_at", (uid,))
    for ch in channels:
        ch["times"] = json.loads(ch["times"])
        ch["freq_label"] = FREQ_LABELS.get(ch["frequency"], ch["frequency"])
        ch["prompt_count"] = db_fetchone("SELECT COUNT(*) AS c FROM prompts WHERE channel_id = %s AND user_id = %s", (ch["id"], uid))["c"]
        ch["content_count"] = db_fetchone("SELECT COUNT(*) AS c FROM contents WHERE channel_id = %s AND user_id = %s", (ch["id"], uid))["c"]
        ch["content_pending"] = db_fetchone("SELECT COUNT(*) AS c FROM contents WHERE channel_id = %s AND user_id = %s AND status = 'pendente'", (ch["id"], uid))["c"]
        fix_dt(ch)
    return jsonify(channels)

@app.route("/api/channels", methods=["POST"])
@login_required
def api_create_channel():
    uid = current_user_id(); data = request.json; ch_id = new_id()
    db_execute("INSERT INTO channels (id, user_id, name, icon, color, frequency, times, first_day_on) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (ch_id, uid, data["name"], data.get("icon","📺"), data.get("color","#2563eb"), data.get("frequency","1x_dia"), json.dumps(data.get("times",["08:00"])), data.get("first_day_on") or None))
    db_commit(); return jsonify({"id": ch_id, "ok": True})

@app.route("/api/channels/<ch_id>", methods=["PUT"])
@login_required
def api_update_channel(ch_id):
    uid = current_user_id(); data = request.json
    db_execute("UPDATE channels SET name=%s, icon=%s, color=%s, frequency=%s, times=%s, first_day_on=%s WHERE id=%s AND user_id=%s",
        (data["name"], data.get("icon","📺"), data.get("color","#2563eb"), data.get("frequency","1x_dia"), json.dumps(data.get("times",["08:00"])), data.get("first_day_on") or None, ch_id, uid))
    db_commit(); return jsonify({"ok": True})

@app.route("/api/channels/<ch_id>", methods=["DELETE"])
@login_required
def api_delete_channel(ch_id):
    uid = current_user_id()
    db_execute("DELETE FROM channels WHERE id = %s AND user_id = %s", (ch_id, uid))
    db_commit(); return jsonify({"ok": True})

# ── API: Prompts ──

@app.route("/api/prompts/<channel_id>")
@login_required
def api_prompts(channel_id):
    uid = current_user_id()
    prompts = db_fetchall("SELECT * FROM prompts WHERE channel_id = %s AND user_id = %s ORDER BY created_at", (channel_id, uid))
    for p in prompts: fix_dt(p)
    return jsonify(prompts)

@app.route("/api/prompts", methods=["POST"])
@login_required
def api_create_prompt():
    uid = current_user_id(); data = request.json; pr_id = new_id()
    db_execute("INSERT INTO prompts (id, user_id, channel_id, name, category, content) VALUES (%s,%s,%s,%s,%s,%s)",
        (pr_id, uid, data["channel_id"], data["name"], data.get("category",""), data.get("content","")))
    db_commit(); return jsonify({"id": pr_id, "ok": True})

@app.route("/api/prompts/<pr_id>", methods=["PUT"])
@login_required
def api_update_prompt(pr_id):
    uid = current_user_id(); data = request.json
    db_execute("UPDATE prompts SET name=%s, category=%s, content=%s WHERE id=%s AND user_id=%s",
        (data["name"], data.get("category",""), data.get("content",""), pr_id, uid))
    db_commit(); return jsonify({"ok": True})

@app.route("/api/prompts/<pr_id>", methods=["DELETE"])
@login_required
def api_delete_prompt(pr_id):
    uid = current_user_id()
    db_execute("DELETE FROM prompts WHERE id = %s AND user_id = %s", (pr_id, uid))
    db_commit(); return jsonify({"ok": True})

@app.route("/api/prompts/<pr_id>/detail")
@login_required
def api_prompt_detail(pr_id):
    uid = current_user_id()
    pr = db_fetchone("SELECT * FROM prompts WHERE id = %s AND user_id = %s", (pr_id, uid))
    if not pr: return jsonify({"error": "not found"}), 404
    fix_dt(pr); return jsonify(pr)

# ── API: Contents ──

@app.route("/api/contents/<channel_id>")
@login_required
def api_contents(channel_id):
    uid = current_user_id(); sf = request.args.get("status", "")
    if sf: contents = db_fetchall("SELECT * FROM contents WHERE channel_id=%s AND user_id=%s AND status=%s ORDER BY created_at DESC", (channel_id, uid, sf))
    else: contents = db_fetchall("SELECT * FROM contents WHERE channel_id=%s AND user_id=%s ORDER BY CASE status WHEN 'pendente' THEN 0 WHEN 'publicado' THEN 1 END, created_at DESC", (channel_id, uid))
    for c in contents: fix_dt(c)
    return jsonify(contents)

@app.route("/api/contents", methods=["POST"])
@login_required
def api_create_content():
    uid = current_user_id()
    data = request.json; ct_id = new_id()
    thumb = data.get("thumbnail") or None
    db_execute("INSERT INTO contents (id, user_id, channel_id, title, status, published_at, thumbnail) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (ct_id, uid, data["channel_id"], data["title"], data.get("status","pendente"), data.get("published_at") or None, thumb))
    db_commit(); return jsonify({"id": ct_id, "ok": True})

@app.route("/api/contents/<ct_id>", methods=["PUT"])
@login_required
def api_update_content(ct_id):
    uid = current_user_id(); data = request.json
    if "thumbnail" in data:
        db_execute("UPDATE contents SET title=%s, status=%s, published_at=%s, thumbnail=%s WHERE id=%s AND user_id=%s",
            (data["title"], data.get("status","pendente"), data.get("published_at") or None, data.get("thumbnail") or None, ct_id, uid))
    else:
        db_execute("UPDATE contents SET title=%s, status=%s, published_at=%s WHERE id=%s AND user_id=%s",
            (data["title"], data.get("status","pendente"), data.get("published_at") or None, ct_id, uid))
    db_commit(); return jsonify({"ok": True})

@app.route("/api/contents/<ct_id>/thumbnail", methods=["POST"])
@login_required
def api_upload_thumbnail(ct_id):
    uid = current_user_id()
    ct = db_fetchone("SELECT id FROM contents WHERE id = %s AND user_id = %s", (ct_id, uid))
    if not ct: return jsonify({"error": "not found"}), 404
    if 'file' in request.files:
        f = request.files['file']
        if f and f.filename:
            data = f.read()
            mime = f.content_type or 'image/jpeg'
            b64 = base64.b64encode(data).decode('utf-8')
            thumb_data = f"data:{mime};base64,{b64}"
            db_execute("UPDATE contents SET thumbnail=%s WHERE id=%s AND user_id=%s", (thumb_data, ct_id, uid))
            db_commit()
            return jsonify({"ok": True, "thumbnail": thumb_data})
    return jsonify({"error": "no file"}), 400

@app.route("/api/contents/<ct_id>/thumbnail", methods=["DELETE"])
@login_required
def api_delete_thumbnail(ct_id):
    uid = current_user_id()
    db_execute("UPDATE contents SET thumbnail=NULL WHERE id=%s AND user_id=%s", (ct_id, uid))
    db_commit(); return jsonify({"ok": True})

@app.route("/api/contents/<ct_id>/detail")
@login_required
def api_content_detail(ct_id):
    uid = current_user_id()
    ct = db_fetchone("SELECT * FROM contents WHERE id = %s AND user_id = %s", (ct_id, uid))
    if not ct: return jsonify({"error": "not found"}), 404
    fix_dt(ct); return jsonify(ct)

@app.route("/api/contents/<ct_id>/toggle", methods=["POST"])
@login_required
def api_toggle_content(ct_id):
    uid = current_user_id()
    ct = db_fetchone("SELECT * FROM contents WHERE id = %s AND user_id = %s", (ct_id, uid))
    if not ct: return jsonify({"error": "not found"}), 404
    if ct["status"] == "pendente": new_status = "publicado"; pub_date = datetime.now().strftime("%Y-%m-%d")
    else: new_status = "pendente"; pub_date = None
    db_execute("UPDATE contents SET status=%s, published_at=%s WHERE id=%s AND user_id=%s", (new_status, pub_date, ct_id, uid))
    db_commit(); return jsonify({"ok": True, "status": new_status, "published_at": pub_date})

@app.route("/api/contents/<ct_id>", methods=["DELETE"])
@login_required
def api_delete_content(ct_id):
    uid = current_user_id()
    db_execute("DELETE FROM contents WHERE id = %s AND user_id = %s", (ct_id, uid))
    db_commit(); return jsonify({"ok": True})

@app.route("/api/contents-stats")
@login_required
def api_contents_stats():
    uid = current_user_id()
    total = db_fetchone("SELECT COUNT(*) AS c FROM contents WHERE user_id = %s", (uid,))["c"]
    published = db_fetchone("SELECT COUNT(*) AS c FROM contents WHERE user_id = %s AND status = 'publicado'", (uid,))["c"]
    return jsonify({"total": total, "published": published, "pending": total - published})


# ── API: Achievements ──

@app.route("/api/achievements")
@login_required
def api_achievements():
    uid = current_user_id()
    achs = db_fetchall("""
        SELECT a.*, c.name as channel_name, c.icon as channel_icon, c.color as channel_color 
        FROM achievements a 
        LEFT JOIN channels c ON a.channel_id = c.id 
        WHERE a.user_id = %s 
        ORDER BY a.achieved_at DESC NULLS LAST, a.created_at DESC
    """, (uid,))
    for a in achs: fix_dt(a)
    return jsonify(achs)

@app.route("/api/achievements", methods=["POST"])
@login_required
def api_create_achievement():
    uid = current_user_id()
    data = request.json; ach_id = new_id()
    db_execute("""INSERT INTO achievements (id, user_id, channel_id, title, description, achieved_at, image) 
        VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (ach_id, uid, data.get("channel_id") or None, data["title"], 
         data.get("description") or None, data.get("achieved_at") or None, data.get("image") or None))
    db_commit(); return jsonify({"id": ach_id, "ok": True})

@app.route("/api/achievements/<ach_id>", methods=["PUT"])
@login_required
def api_update_achievement(ach_id):
    uid = current_user_id(); data = request.json
    if "image" in data:
        db_execute("""UPDATE achievements SET title=%s, description=%s, achieved_at=%s, channel_id=%s, image=%s 
            WHERE id=%s AND user_id=%s""",
            (data["title"], data.get("description") or None, data.get("achieved_at") or None,
             data.get("channel_id") or None, data.get("image") or None, ach_id, uid))
    else:
        db_execute("""UPDATE achievements SET title=%s, description=%s, achieved_at=%s, channel_id=%s 
            WHERE id=%s AND user_id=%s""",
            (data["title"], data.get("description") or None, data.get("achieved_at") or None,
             data.get("channel_id") or None, ach_id, uid))
    db_commit(); return jsonify({"ok": True})

@app.route("/api/achievements/<ach_id>", methods=["DELETE"])
@login_required
def api_delete_achievement(ach_id):
    uid = current_user_id()
    db_execute("DELETE FROM achievements WHERE id = %s AND user_id = %s", (ach_id, uid))
    db_commit(); return jsonify({"ok": True})

@app.route("/api/achievements/<ach_id>/detail")
@login_required
def api_achievement_detail(ach_id):
    uid = current_user_id()
    ach = db_fetchone("SELECT * FROM achievements WHERE id = %s AND user_id = %s", (ach_id, uid))
    if not ach: return jsonify({"error": "not found"}), 404
    fix_dt(ach); return jsonify(ach)


# ────────────────────────────── MAIN ────────────────────────────────

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  ⚡ FlowCast Planner rodando em http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
