import os
import json
import secrets
import hashlib
import hmac
from functools import wraps

import psycopg
from psycopg.rows import dict_row
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not configured. Connect this Render service to a Render PostgreSQL database.")

MAX_HOUSE_BYTES = 10 * 1024 * 1024


def get_db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(32) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                api_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS houses (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                size_bytes BIGINT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_houses_user_id
            ON houses(user_id)
        """)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username, api_token FROM users WHERE id = %s",
            (user_id,)
        ).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper


def bearer_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None

    token = header[7:].strip()
    if not token:
        return None

    with get_db() as conn:
        return conn.execute(
            "SELECT id, username, api_token FROM users WHERE api_token = %s",
            (token,)
        ).fetchone()


def valid_house_content(content):
    if not content:
        return False, "House file is empty."

    if len(content.encode("utf-8")) > MAX_HOUSE_BYTES:
        return False, "House file is too large (10 MB maximum)."

    try:
        json.loads(content)
    except json.JSONDecodeError:
        return False, "House file must contain valid JSON."

    return True, None


@app.before_request
def startup():
    if not getattr(app, "_db_initialized", False):
        init_db()
        app._db_initialized = True


@app.route("/")
def index():
    if get_current_user():
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not 3 <= len(username) <= 32:
        flash("Username must be 3–32 characters.", "error")
        return redirect(url_for("index"))

    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("index"))

    token = secrets.token_urlsafe(32)

    try:
        with get_db() as conn:
            user = conn.execute("""
                INSERT INTO users (username, password_hash, api_token)
                VALUES (%s, %s, %s)
                RETURNING id
            """, (username, hash_password(password), token)).fetchone()
            session["user_id"] = user["id"]
    except psycopg.errors.UniqueViolation:
        flash("That username is already taken.", "error")
        return redirect(url_for("index"))

    flash("Account created successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with get_db() as conn:
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = %s",
            (username,)
        ).fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        flash("Invalid username or password.", "error")
        return redirect(url_for("index"))

    session["user_id"] = user["id"]
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    with get_db() as conn:
        houses = conn.execute("""
            SELECT id, name, size_bytes, created_at, updated_at
            FROM houses
            WHERE user_id = %s
            ORDER BY updated_at DESC
        """, (user["id"],)).fetchall()

    return render_template("dashboard.html", user=user, houses=houses)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    user = get_current_user()
    files = request.files.getlist("files")

    if not files:
        flash("Choose at least one house file.", "error")
        return redirect(url_for("dashboard"))

    added = 0
    errors = []

    with get_db() as conn:
        for file in files:
            if not file.filename:
                continue

            name = os.path.basename(file.filename)
            content = file.read().decode("utf-8", errors="replace")

            ok, error = valid_house_content(content)
            if not ok:
                errors.append(f"{name}: {error}")
                continue

            conn.execute("""
                INSERT INTO houses (user_id, name, content, size_bytes)
                VALUES (%s, %s, %s, %s)
            """, (user["id"], name, content, len(content.encode("utf-8"))))
            added += 1

    if added:
        flash(f"Uploaded {added} house file(s).", "success")
    for error in errors:
        flash(error, "error")

    return redirect(url_for("dashboard"))


@app.route("/delete/<int:house_id>", methods=["POST"])
@login_required
def delete_house(house_id):
    user = get_current_user()
    with get_db() as conn:
        conn.execute(
            "DELETE FROM houses WHERE id = %s AND user_id = %s",
            (house_id, user["id"])
        )
    return redirect(url_for("dashboard"))


# =========================
# Roblox / Cubix API
# =========================

@app.route("/api/me")
def api_me():
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "id": user["id"],
        "username": user["username"]
    })


@app.route("/api/houses", methods=["GET"])
def api_list_houses():
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, name, size_bytes, created_at, updated_at
            FROM houses
            WHERE user_id = %s
            ORDER BY updated_at DESC
        """, (user["id"],)).fetchall()

    return jsonify({
        "houses": [
            {
                "id": row["id"],
                "name": row["name"],
                "size_bytes": row["size_bytes"],
                "created_at": row["created_at"].isoformat(),
                "updated_at": row["updated_at"].isoformat()
            }
            for row in rows
        ]
    })


@app.route("/api/houses", methods=["POST"])
def api_create_house():
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    content = data.get("content")

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not isinstance(content, str):
        return jsonify({"error": "content must be a JSON string"}), 400

    ok, error = valid_house_content(content)
    if not ok:
        return jsonify({"error": error}), 400

    with get_db() as conn:
        row = conn.execute("""
            INSERT INTO houses (user_id, name, content, size_bytes)
            VALUES (%s, %s, %s, %s)
            RETURNING id, name, size_bytes, created_at, updated_at
        """, (
            user["id"],
            name[:255],
            content,
            len(content.encode("utf-8"))
        )).fetchone()

    return jsonify({
        "success": True,
        "house": {
            "id": row["id"],
            "name": row["name"],
            "size_bytes": row["size_bytes"],
            "created_at": row["created_at"].isoformat(),
            "updated_at": row["updated_at"].isoformat()
        }
    }), 201


@app.route("/api/houses/<int:house_id>", methods=["GET"])
def api_get_house(house_id):
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        row = conn.execute("""
            SELECT id, name, content, size_bytes, created_at, updated_at
            FROM houses
            WHERE id = %s AND user_id = %s
        """, (house_id, user["id"])).fetchone()

    if not row:
        return jsonify({"error": "House not found"}), 404

    return jsonify({
        "id": row["id"],
        "name": row["name"],
        "content": row["content"],
        "size_bytes": row["size_bytes"],
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat()
    })


@app.route("/api/houses/<int:house_id>", methods=["DELETE"])
def api_delete_house(house_id):
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        result = conn.execute("""
            DELETE FROM houses
            WHERE id = %s AND user_id = %s
            RETURNING id
        """, (house_id, user["id"])).fetchone()

    if not result:
        return jsonify({"error": "House not found"}), 404

    return jsonify({"success": True})


@app.route("/health")
def health():
    try:
        with get_db() as conn:
            conn.execute("SELECT 1")
        return jsonify({"status": "ok", "database": "postgresql"})
    except Exception as exc:
        return jsonify({"status": "error", "database": "postgresql", "message": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
