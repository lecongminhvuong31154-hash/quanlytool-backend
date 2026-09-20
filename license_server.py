# -*- coding: utf-8 -*-
import os
import re
import json
import hmac
import base64
import hashlib
import secrets
import sqlite3
import calendar
import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
ADMIN_HTML_PATH = os.path.join(BASE_DIR, "admin.html")

# Railway/production uses environment variables.
# config.json remains an optional local-development fallback.
_file_config = {}
if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            _file_config = json.load(f)
    except Exception:
        _file_config = {}

def _env_or_file(env_name, file_name, default=""):
    value = os.environ.get(env_name)
    if value is not None and str(value).strip() != "":
        return value
    return _file_config.get(file_name, default)

allowed_from_env = os.environ.get("ALLOWED_ORIGINS", "").strip()
if allowed_from_env:
    allowed_origins = [
        x.strip().rstrip("/")
        for x in allowed_from_env.split(",")
        if x.strip()
    ]
else:
    allowed_origins = _file_config.get("allowed_origins", [])

CONFIG = {
    "admin_user": _env_or_file("ADMIN_USER", "admin_user", "admin"),
    "admin_password": _env_or_file(
        "ADMIN_PASSWORD", "admin_password", "CHANGE-ME"
    ),
    "tool_name": _env_or_file("TOOL_NAME", "tool_name", "Move To Blue"),
    "allowed_origins": allowed_origins,
}

# Mount a Railway Volume at /data and set DB_PATH=/data/license_manager.db.
DB_PATH = os.environ.get(
    "DB_PATH",
    _file_config.get(
        "db_path",
        os.path.join(BASE_DIR, "license_manager.db")
    )
)

TOOL_NAME = CONFIG.get("tool_name", "Move To Blue")


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS tool_settings (
            id INTEGER PRIMARY KEY CHECK(id=1),
            tool_name TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            locked INTEGER NOT NULL DEFAULT 0,
            default_max_devices INTEGER NOT NULL DEFAULT 1
        );
        INSERT OR IGNORE INTO tool_settings
        (id,tool_name,active,locked,default_max_devices)
        VALUES (1,'Move To Blue',1,0,1);

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL UNIQUE COLLATE NOCASE,
            key_hash TEXT NOT NULL,
            key_preview TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            max_devices INTEGER NOT NULL DEFAULT 1,
            locked INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            device_name TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(account_id,device_id),
            FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
        );
        """)


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(value):
    return datetime.datetime.fromisoformat(value)


def add_months(dt, months):
    total = dt.year * 12 + dt.month - 1 + int(months)
    year, month0 = divmod(total, 12)
    month = month0 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def hash_key(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def make_key():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(4))
        for _ in range(4)
    )


def valid_user_id(value):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", value or ""))


def read_json(handler):
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length else b"{}"
    return json.loads(raw.decode("utf-8"))


def send_json(handler, status, data):
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def send_html(handler, status, html):
    body = html.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def basic_auth_ok(handler):
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False

    try:
        decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        return False

    return (
        hmac.compare_digest(username, str(CONFIG["admin_user"]))
        and hmac.compare_digest(password, str(CONFIG["admin_password"]))
    )


def require_admin(handler):
    if basic_auth_ok(handler):
        return True

    handler.send_response(401)
    handler.send_header("WWW-Authenticate", 'Basic realm="Tool Manager Admin"')
    handler.end_headers()
    return False


class Handler(BaseHTTPRequestHandler):
    def _allowed_origin(self):
        origin = self.headers.get("Origin", "")
        allowed = CONFIG.get("allowed_origins", [])
        if origin and origin in allowed:
            return origin
        return ""

    def end_headers(self):
        origin = self._allowed_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type"
            )
            self.send_header(
                "Access-Control-Allow-Methods",
                "GET, POST, OPTIONS"
            )
            self.send_header("Access-Control-Max-Age", "86400")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/health":
            return send_json(self, 200, {
                "ok": True,
                "service": "Move To Blue License API"
            })

        if path in ("/", "/admin"):
            if not require_admin(self):
                return
            with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
                return send_html(self, 200, f.read())

        if path == "/api/admin/tool":
            if not require_admin(self):
                return
            with db() as conn:
                row = conn.execute(
                    "SELECT * FROM tool_settings WHERE id=1"
                ).fetchone()
            return send_json(self, 200, dict(row))

        if path == "/api/admin/stats":
            if not require_admin(self):
                return
            with db() as conn:
                accounts = conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
                devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            return send_json(self, 200, {"accounts": accounts, "devices": devices})

        if path == "/api/admin/accounts":
            if not require_admin(self):
                return
            return self.get_accounts()

        return send_json(self, 404, {"ok": False, "message": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/license/login":
            return self.license_login()

        if not path.startswith("/api/admin/"):
            return send_json(self, 404, {"ok": False, "message": "Not found"})

        if not require_admin(self):
            return

        if path == "/api/admin/tool":
            return self.save_tool()

        if path == "/api/admin/accounts":
            return self.create_account()

        match = re.fullmatch(
            r"/api/admin/accounts/(\d+)/(extend|lock|reset-key|devices/delete)",
            path
        )
        if not match:
            return send_json(self, 404, {"ok": False, "message": "Not found"})

        account_id = int(match.group(1))
        action = match.group(2)

        if action == "extend":
            return self.extend_account(account_id)
        if action == "lock":
            return self.lock_account(account_id)
        if action == "reset-key":
            return self.reset_key(account_id)
        if action == "devices/delete":
            return self.delete_device(account_id)

    def save_tool(self):
        data = read_json(self)
        active = 1 if data.get("active") else 0
        locked = 1 if data.get("locked") else 0
        default_max = max(1, min(100, int(data.get("default_max_devices", 1))))

        with db() as conn:
            conn.execute(
                """UPDATE tool_settings
                   SET active=?,locked=?,default_max_devices=?
                   WHERE id=1""",
                (active, locked, default_max)
            )

        return send_json(self, 200, {"ok": True})

    def create_account(self):
        data = read_json(self)
        user_id = str(data.get("user_id", "")).strip()
        months = max(1, min(120, int(data.get("months", 1))))
        max_devices = max(1, min(100, int(data.get("max_devices", 1))))

        if not valid_user_id(user_id):
            return send_json(self, 400, {
                "ok": False,
                "message": "ID chỉ dùng chữ, số, dấu _ . - và dài 3-32 ký tự."
            })

        plain_key = make_key()
        created = now_utc()
        expires = add_months(created, months)

        try:
            with db() as conn:
                conn.execute(
                    """INSERT INTO accounts
                    (user_id,key_hash,key_preview,created_at,expires_at,max_devices,locked)
                    VALUES (?,?,?,?,?,?,0)""",
                    (
                        user_id,
                        hash_key(plain_key),
                        plain_key[:4] + "-****-****-" + plain_key[-4:],
                        iso(created),
                        iso(expires),
                        max_devices
                    )
                )
        except sqlite3.IntegrityError:
            return send_json(self, 409, {
                "ok": False,
                "message": "ID này đã tồn tại."
            })

        return send_json(self, 201, {
            "ok": True,
            "user_id": user_id,
            "key": plain_key,
            "expires_at": iso(expires)
        })

    def get_accounts(self):
        with db() as conn:
            rows = conn.execute(
                "SELECT * FROM accounts ORDER BY id DESC"
            ).fetchall()

            now = now_utc()
            accounts = []

            for row in rows:
                devices = conn.execute(
                    "SELECT * FROM devices WHERE account_id=? ORDER BY id",
                    (row["id"],)
                ).fetchall()

                item = dict(row)
                item.pop("key_hash", None)
                item["expired"] = parse_iso(row["expires_at"]) < now
                item["locked"] = bool(row["locked"])
                item["devices"] = [dict(x) for x in devices]
                accounts.append(item)

        return send_json(self, 200, {"accounts": accounts})

    def extend_account(self, account_id):
        data = read_json(self)
        months = max(1, min(120, int(data.get("months", 1))))
        now = now_utc()

        with db() as conn:
            row = conn.execute(
                "SELECT expires_at FROM accounts WHERE id=?",
                (account_id,)
            ).fetchone()

            if not row:
                return send_json(self, 404, {"ok": False, "message": "Không tìm thấy ID."})

            current = parse_iso(row["expires_at"])
            base = current if current > now else now
            new_exp = add_months(base, months)

            conn.execute(
                "UPDATE accounts SET expires_at=? WHERE id=?",
                (iso(new_exp), account_id)
            )

        return send_json(self, 200, {"ok": True, "expires_at": iso(new_exp)})

    def lock_account(self, account_id):
        data = read_json(self)
        locked = 1 if data.get("locked") else 0

        with db() as conn:
            conn.execute(
                "UPDATE accounts SET locked=? WHERE id=?",
                (locked, account_id)
            )

        return send_json(self, 200, {"ok": True})

    def reset_key(self, account_id):
        plain_key = make_key()

        with db() as conn:
            cur = conn.execute(
                """UPDATE accounts
                   SET key_hash=?,key_preview=?
                   WHERE id=?""",
                (
                    hash_key(plain_key),
                    plain_key[:4] + "-****-****-" + plain_key[-4:],
                    account_id
                )
            )
            if cur.rowcount == 0:
                return send_json(self, 404, {"ok": False, "message": "Không tìm thấy ID."})

        return send_json(self, 200, {"ok": True, "key": plain_key})

    def delete_device(self, account_id):
        data = read_json(self)
        device_id = str(data.get("device_id", "")).strip()

        with db() as conn:
            conn.execute(
                "DELETE FROM devices WHERE account_id=? AND device_id=?",
                (account_id, device_id)
            )

        return send_json(self, 200, {"ok": True})

    def license_login(self):
        try:
            data = read_json(self)
        except Exception:
            return send_json(self, 400, {
                "ok": False,
                "message": "Dữ liệu không hợp lệ."
            })

        user_id = str(data.get("user_id", "")).strip()
        key = str(data.get("key", "")).strip()
        device_id = str(data.get("device_id", "")).strip()
        device_name = str(data.get("device_name", "")).strip()[:120]

        if not user_id or not key or not device_id:
            return send_json(self, 400, {
                "ok": False,
                "message": "Thiếu ID, KEY hoặc Device ID."
            })

        with db() as conn:
            tool = conn.execute(
                "SELECT * FROM tool_settings WHERE id=1"
            ).fetchone()

            if not tool["active"] or tool["locked"]:
                return send_json(self, 403, {
                    "ok": False,
                    "reason": "tool_locked",
                    "message": "Tool hiện đang bị quản trị viên tạm khóa."
                })

            account = conn.execute(
                "SELECT * FROM accounts WHERE user_id=? COLLATE NOCASE",
                (user_id,)
            ).fetchone()

            if not account or not hmac.compare_digest(
                account["key_hash"],
                hash_key(key)
            ):
                return send_json(self, 403, {
                    "ok": False,
                    "reason": "invalid_credentials",
                    "message": "ID hoặc KEY không đúng."
                })

            if account["locked"]:
                return send_json(self, 403, {
                    "ok": False,
                    "reason": "account_locked",
                    "message": "ID này đã bị quản trị viên khóa."
                })

            if parse_iso(account["expires_at"]) < now_utc():
                return send_json(self, 403, {
                    "ok": False,
                    "reason": "expired",
                    "message": "Tài khoản đã hết hạn. Vui lòng liên hệ chủ tool để gia hạn."
                })

            existing = conn.execute(
                "SELECT * FROM devices WHERE account_id=? AND device_id=?",
                (account["id"], device_id)
            ).fetchone()

            current = iso(now_utc())

            if existing:
                conn.execute(
                    "UPDATE devices SET last_seen=?,device_name=? WHERE id=?",
                    (current, device_name, existing["id"])
                )
            else:
                count = conn.execute(
                    "SELECT COUNT(*) FROM devices WHERE account_id=?",
                    (account["id"],)
                ).fetchone()[0]

                if count >= account["max_devices"]:
                    return send_json(self, 403, {
                        "ok": False,
                        "reason": "device_limit",
                        "message": (
                            f"Tài khoản đã đủ {account['max_devices']} thiết bị. "
                            "Hãy liên hệ chủ tool để xóa thiết bị cũ."
                        )
                    })

                conn.execute(
                    """INSERT INTO devices
                    (account_id,device_id,device_name,first_seen,last_seen)
                    VALUES (?,?,?,?,?)""",
                    (
                        account["id"],
                        device_id,
                        device_name,
                        current,
                        current
                    )
                )

        return send_json(self, 200, {
            "ok": True,
            "tool": TOOL_NAME,
            "user_id": user_id,
            "expires_at": account["expires_at"]
        })


def main():
    init_db()

    # Railway requires the public HTTP server to listen on 0.0.0.0
    # and on the PORT environment variable supplied by the platform.
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", "8787"))

    db_dir = os.path.dirname(os.path.abspath(DB_PATH))
    os.makedirs(db_dir, exist_ok=True)

    print("=" * 62)
    print("MOVE TO BLUE LICENSE SERVER")
    print(f"Listening on http://{host}:{port}")
    print(f"Database: {DB_PATH}")
    print(f"Admin user: {CONFIG['admin_user']}")
    print(f"Allowed origins: {CONFIG.get('allowed_origins', [])}")
    if CONFIG.get("admin_password") in ("CHANGE-ME", "CHANGE-ME-123456", ""):
        print("CANH BAO: Hay dat ADMIN_PASSWORD tren hosting.")
    print("=" * 62)

    server = ThreadingHTTPServer((host, port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
