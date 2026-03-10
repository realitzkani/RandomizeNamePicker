import os
import sqlite3
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Config ────────────────────────────────────────────────────────────────────
JWT_SECRET   = os.environ.get('JWT_SECRET',   'change-this-in-production-please')
OWNER_TOKEN  = os.environ.get('OWNER_TOKEN',  'owner-secret')
DB_PATH      = os.path.join(os.path.dirname(__file__), 'data.db')

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT    UNIQUE NOT NULL COLLATE NOCASE,
                password   TEXT    NOT NULL,
                role       TEXT    NOT NULL DEFAULT 'viewer',
                created_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                joined_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
        """)

# ── Helpers ───────────────────────────────────────────────────────────────────
def make_token(user_id, username, role):
    payload = {
        'id':       user_id,
        'username': username,
        'role':     role,
        'exp':      datetime.now(timezone.utc) + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def decode_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get('Authorization', '')
        if not header.startswith('Bearer '):
            return jsonify({'error': 'Not authenticated'}), 401
        try:
            g.user = decode_token(header[7:])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def err(msg, code=400):
    return jsonify({'error': msg}), code

# ── Health ────────────────────────────────────────────────────────────────────
@app.get('/')
def health():
    return jsonify({'status': 'ok', 'app': 'Name Picker API (Python)'})

# ── Auth: Register ────────────────────────────────────────────────────────────
@app.post('/auth/register')
def register():
    data     = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return err('Username and password are required.')
    if len(username) < 2 or len(username) > 30:
        return err('Username must be 2–30 characters.')
    if len(password) < 4:
        return err('Password must be at least 4 characters.')

    db = get_db()
    if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
        return err('That username is already taken.', 409)

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cur    = db.execute(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        (username, hashed, 'viewer')
    )
    db.commit()

    token = make_token(cur.lastrowid, username, 'viewer')
    return jsonify({'token': token, 'user': {'id': cur.lastrowid, 'username': username, 'role': 'viewer'}})

# ── Auth: Login ───────────────────────────────────────────────────────────────
@app.post('/auth/login')
def login():
    data     = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return err('Username and password are required.')

    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user or not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return err('Incorrect username or password.', 401)

    token = make_token(user['id'], user['username'], user['role'])
    return jsonify({'token': token, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}})

# ── Auth: Me ──────────────────────────────────────────────────────────────────
@app.get('/auth/me')
@require_auth
def me():
    db   = get_db()
    user = db.execute('SELECT id, username, role, created_at FROM users WHERE id = ?', (g.user['id'],)).fetchone()
    if not user:
        return err('User not found.', 404)

    count = db.execute('SELECT COUNT(*) as c FROM sessions WHERE user_id = ?', (user['id'],)).fetchone()['c']
    return jsonify({
        'id':            user['id'],
        'username':      user['username'],
        'role':          user['role'],
        'created_at':    user['created_at'],
        'session_count': count
    })

# ── Auth: Change username ─────────────────────────────────────────────────────
@app.put('/auth/username')
@require_auth
def change_username():
    data     = request.get_json() or {}
    username = (data.get('username') or '').strip()

    if len(username) < 2 or len(username) > 30:
        return err('Username must be 2–30 characters.')

    db = get_db()
    if db.execute('SELECT id FROM users WHERE username = ? AND id != ?', (username, g.user['id'])).fetchone():
        return err('That username is already taken.', 409)

    db.execute('UPDATE users SET username = ? WHERE id = ?', (username, g.user['id']))
    db.commit()

    token = make_token(g.user['id'], username, g.user['role'])
    return jsonify({'token': token, 'username': username})

# ── Auth: Change password ─────────────────────────────────────────────────────
@app.put('/auth/password')
@require_auth
def change_password():
    data        = request.get_json() or {}
    new_password = data.get('newPassword') or ''

    if len(new_password) < 4:
        return err('Password must be at least 4 characters.')

    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    db     = get_db()
    db.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, g.user['id']))
    db.commit()

    token = make_token(g.user['id'], g.user['username'], g.user['role'])
    return jsonify({'token': token})

# ── Auth: Upgrade to admin ────────────────────────────────────────────────────
@app.post('/auth/upgrade')
@require_auth
def upgrade():
    data          = request.get_json() or {}
    admin_password = data.get('adminPassword') or ''

    db      = get_db()
    setting = db.execute("SELECT value FROM settings WHERE key = 'admin_password_hash'").fetchone()
    if not setting:
        return err('No admin password has been set.', 403)

    if not bcrypt.checkpw(admin_password.encode(), setting['value'].encode()):
        return err('Incorrect admin password.', 403)

    db.execute("UPDATE users SET role = 'admin' WHERE id = ?", (g.user['id'],))
    db.commit()

    token = make_token(g.user['id'], g.user['username'], 'admin')
    return jsonify({'token': token, 'role': 'admin'})

# ── Sessions ──────────────────────────────────────────────────────────────────
@app.post('/sessions/join')
@require_auth
def join_session():
    db = get_db()
    db.execute('INSERT INTO sessions (user_id) VALUES (?)', (g.user['id'],))
    db.commit()
    return jsonify({'ok': True})

@app.get('/sessions/mine')
@require_auth
def my_sessions():
    db       = get_db()
    sessions = db.execute(
        'SELECT id, joined_at FROM sessions WHERE user_id = ? ORDER BY joined_at DESC LIMIT 50',
        (g.user['id'],)
    ).fetchall()
    return jsonify([{'id': s['id'], 'joined_at': s['joined_at']} for s in sessions])

# ── Owner: Set admin password ─────────────────────────────────────────────────
@app.post('/owner/set-admin-password')
def set_admin_password():
    data          = request.get_json() or {}
    owner_token   = data.get('ownerToken') or ''
    admin_password = data.get('adminPassword') or ''

    if owner_token != OWNER_TOKEN:
        return err('Not authorized.', 403)
    if not admin_password:
        return err('Password cannot be empty.')

    hashed = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()
    db     = get_db()
    db.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)",
        (hashed,)
    )
    db.commit()
    return jsonify({'ok': True})

@app.delete('/owner/remove-admin-password')
def remove_admin_password():
    data        = request.get_json() or {}
    owner_token = data.get('ownerToken') or ''

    if owner_token != OWNER_TOKEN:
        return err('Not authorized.', 403)

    db = get_db()
    db.execute("DELETE FROM settings WHERE key = 'admin_password_hash'")
    db.commit()
    return jsonify({'ok': True})

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 3001))
    app.run(host='0.0.0.0', port=port)
