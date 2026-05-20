from flask import Flask, request, jsonify, render_template, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
import re
import logging
import secrets
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

def utcnow():
    return datetime.now(timezone.utc).isoformat()

# ── Rate limiting ──────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ── Database ───────────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "devsecops.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS products (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                name     TEXT    NOT NULL,
                price    REAL    NOT NULL CHECK(price >= 0),
                category TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                action    TEXT NOT NULL,
                detail    TEXT,
                ip        TEXT,
                timestamp TEXT NOT NULL
            );
            INSERT OR IGNORE INTO products (id, name, price, category) VALUES
                (1, 'Laptop',     999.99, 'Electronics'),
                (2, 'Headphones', 149.99, 'Electronics'),
                (3, 'Desk Chair', 299.99, 'Furniture'),
                (4, 'Notebook',     4.99, 'Stationery'),
                (5, 'Monitor',    399.99, 'Electronics');
        """)

# ── Input sanitization ─────────────────────────────────────────────────────────
def sanitize_search(query: str) -> str:
    return re.sub(r"[^\w\s\-]", "", query)[:100]

def log_audit(action: str, detail: str = ""):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (action, detail, ip, timestamp) VALUES (?,?,?,?)",
                (action, detail, request.remote_addr, utcnow()),
            )
    except Exception as exc:
        logger.error("Audit log failed: %s", exc)

# ── Security headers on every response ────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers.update({
        "X-Content-Type-Options":    "nosniff",
        "X-Frame-Options":           "DENY",
        "X-XSS-Protection":          "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy":   "default-src 'self'; style-src 'self' 'unsafe-inline'",
        "Referrer-Policy":           "strict-origin-when-cross-origin",
        "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
    })
    return response

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": utcnow()})

@app.route("/api/products", methods=["GET"])
@limiter.limit("30 per minute")
def get_products():
    raw   = request.args.get("search", "")
    clean = sanitize_search(raw)
    log_audit("PRODUCT_SEARCH", clean)
    with get_db() as conn:
        if clean:
            rows = conn.execute(
                "SELECT * FROM products WHERE name LIKE ? OR category LIKE ?",
                (f"%{clean}%", f"%{clean}%"),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM products").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/products/<int:product_id>", methods=["GET"])
def get_product(product_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM products WHERE id = ?", (product_id,)
        ).fetchone()
    if not row:
        abort(404)
    return jsonify(dict(row))

@app.route("/api/products", methods=["POST"])
@limiter.limit("10 per minute")
def create_product():
    data     = request.get_json(silent=True) or {}
    name     = str(data.get("name",     "")).strip()[:200]
    category = str(data.get("category", "")).strip()[:100]
    try:
        price = float(data.get("price", 0))
        assert price >= 0
    except (ValueError, TypeError, AssertionError):
        return jsonify({"error": "price must be a non-negative number"}), 400
    if not name or not category:
        return jsonify({"error": "name and category are required"}), 400
    with get_db() as conn:
        cur    = conn.execute(
            "INSERT INTO products (name, price, category) VALUES (?,?,?)",
            (name, price, category),
        )
        new_id = cur.lastrowid
    log_audit("PRODUCT_CREATE", f"id={new_id} name={name}")
    return jsonify({"id": new_id, "name": name, "price": price, "category": category}), 201

# ── Error handlers ─────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "not found"}), 404

@app.errorhandler(429)
def rate_limited(_):
    return jsonify({"error": "rate limit exceeded"}), 429

@app.errorhandler(500)
def server_error(_):
    logger.exception("Internal server error")
    return jsonify({"error": "internal server error"}), 500

# Initialise DB at import time — runs under both `python app.py` AND gunicorn
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))