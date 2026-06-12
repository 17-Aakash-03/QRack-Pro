import sqlite3
import hashlib
import random
import string

DB_FILE = "qrack.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            can_edit INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            qr_id TEXT NOT NULL,
            scanned_by TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            remark TEXT,
            verification_status TEXT
        );
        CREATE TABLE IF NOT EXISTS excel_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shared INTEGER DEFAULT 0,
            access_code TEXT,
            shared_at DATETIME
        );
    ''')
    try:
        c.execute("ALTER TABLE users ADD COLUMN can_edit INTEGER DEFAULT 0")
    except: pass
    try:
        c.execute("ALTER TABLE excel_access ADD COLUMN access_code TEXT")
    except: pass
    row = c.execute("SELECT * FROM excel_access").fetchone()
    if not row:
        code = gen_code()
        c.execute("INSERT INTO excel_access (shared, access_code) VALUES (0, ?)", (code,))
    head = c.execute("SELECT * FROM users WHERE role='head'").fetchone()
    if not head:
        pwd = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, role, can_edit) VALUES (?, ?, ?, ?)",
                  ("teamhead", pwd, "head", 1))
    conn.commit()
    conn.close()

def gen_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

def get_user(username):
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return u

def create_user(username, password, role='member', can_edit=0):
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password, role, can_edit) VALUES (?, ?, ?, ?)",
                     (username, hash_password(password), role, can_edit))
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False

def update_user_permission(uid, can_edit):
    conn = get_db()
    conn.execute("UPDATE users SET can_edit=? WHERE id=?", (can_edit, uid))
    conn.commit()
    conn.close()

def log_scan(qr_id, scanned_by, remark, verification_status):
    conn = get_db()
    ex = conn.execute("SELECT id FROM scan_logs WHERE qr_id=?", (qr_id,)).fetchone()
    if ex:
        conn.execute("UPDATE scan_logs SET scanned_by=?,timestamp=CURRENT_TIMESTAMP,remark=?,verification_status=? WHERE qr_id=?",
                     (scanned_by, remark, verification_status, qr_id))
    else:
        conn.execute("INSERT INTO scan_logs (qr_id,scanned_by,remark,verification_status) VALUES (?,?,?,?)",
                     (qr_id, scanned_by, remark, verification_status))
    conn.commit()
    conn.close()

def get_scan_logs():
    conn = get_db()
    logs = conn.execute("SELECT * FROM scan_logs ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(l) for l in logs]

def get_all_users():
    conn = get_db()
    users = conn.execute("SELECT id,username,role,can_edit FROM users").fetchall()
    conn.close()
    return [dict(u) for u in users]

def delete_user(uid):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()

def set_excel_shared(shared):
    conn = get_db()
    conn.execute("UPDATE excel_access SET shared=?,shared_at=CURRENT_TIMESTAMP", (1 if shared else 0,))
    conn.commit()
    conn.close()

def get_excel_access():
    conn = get_db()
    row = conn.execute("SELECT * FROM excel_access").fetchone()
    conn.close()
    return dict(row) if row else {"shared": 0, "access_code": ""}

def regenerate_code():
    conn = get_db()
    code = gen_code()
    conn.execute("UPDATE excel_access SET access_code=?", (code,))
    conn.commit()
    conn.close()
    return code

def verify_access_code(code):
    conn = get_db()
    row = conn.execute("SELECT * FROM excel_access WHERE access_code=? AND shared=1", (code,)).fetchone()
    conn.close()
    return row is not None