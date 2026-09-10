import os
import json
import secrets
import hashlib
import hmac
from functools import wraps
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from io import BytesIO

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
                furniture_count INTEGER NOT NULL DEFAULT 0,
                texture_count INTEGER NOT NULL DEFAULT 0,
                house_type VARCHAR(120) NOT NULL DEFAULT '-',
                has_ambiance BOOLEAN NOT NULL DEFAULT FALSE,
                tags TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Safe migrations for installations created by the older Cubix Cloud version.
        for statement in [
            "ALTER TABLE houses ADD COLUMN IF NOT EXISTS furniture_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE houses ADD COLUMN IF NOT EXISTS texture_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE houses ADD COLUMN IF NOT EXISTS house_type VARCHAR(120) NOT NULL DEFAULT '-'",
            "ALTER TABLE houses ADD COLUMN IF NOT EXISTS has_ambiance BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE houses ADD COLUMN IF NOT EXISTS tags TEXT NOT NULL DEFAULT ''",
        ]:
            conn.execute(statement)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_houses_user_id ON houses(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_houses_updated_at ON houses(updated_at DESC)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS favorites (
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                house_id BIGINT NOT NULL REFERENCES houses(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, house_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS house_versions (
                id BIGSERIAL PRIMARY KEY,
                house_id BIGINT NOT NULL REFERENCES houses(id) ON DELETE CASCADE,
                version_number INTEGER NOT NULL,
                content TEXT NOT NULL,
                size_bytes BIGINT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(house_id, version_number)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_house_versions_house_id ON house_versions(house_id, version_number DESC)")


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
            "SELECT id, username, api_token, created_at FROM users WHERE id = %s",
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
    if not isinstance(content, str) or not content.strip():
        return False, "House file is empty."
    if len(content.encode("utf-8")) > MAX_HOUSE_BYTES:
        return False, "House file is too large (10 MB maximum)."
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        return False, f"House file must contain valid JSON ({exc.msg})."
    if not isinstance(parsed, (dict, list)):
        return False, "House JSON must be an object or array."
    return True, None


def house_metadata(content):
    try:
        obj = json.loads(content)
    except Exception:
        return 0, 0, "-", False
    if not isinstance(obj, dict):
        return 0, 0, "-", False
    furniture = obj.get("furniture") or {}
    textures = obj.get("textures") or {}
    furniture_count = len(furniture) if isinstance(furniture, (dict, list)) else 0
    texture_count = len(textures) if isinstance(textures, (dict, list)) else 0
    house_type = str(obj.get("building_type") or obj.get("house_type") or "-")[:120]
    has_ambiance = bool(obj.get("ambiance"))
    return furniture_count, texture_count, house_type, has_ambiance


def serialize_house(row, favorite=False, include_content=False):
    item = {
        "id": row["id"],
        "name": row["name"],
        "size_bytes": row["size_bytes"],
        "furniture_count": row.get("furniture_count", 0),
        "texture_count": row.get("texture_count", 0),
        "house_type": row.get("house_type", "-"),
        "has_ambiance": bool(row.get("has_ambiance", False)),
        "tags": row.get("tags", ""),
        "favorite": bool(favorite),
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat(),
    }
    if include_content:
        item["content"] = row["content"]
        item["data"] = row["content"]
    return item


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
    if not username.replace("_", "").isalnum():
        flash("Username can only contain letters, numbers and underscores.", "error")
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
            SELECT h.*, EXISTS(
                SELECT 1 FROM favorites f WHERE f.house_id = h.id AND f.user_id = %s
            ) AS favorite
            FROM houses h
            WHERE h.user_id = %s
            ORDER BY h.updated_at DESC
        """, (user["id"], user["id"])).fetchall()
        stats = conn.execute("""
            SELECT COUNT(*) AS house_count,
                   COALESCE(SUM(size_bytes), 0) AS storage_bytes,
                   COALESCE(SUM(furniture_count), 0) AS furniture_count,
                   COALESCE(SUM(texture_count), 0) AS texture_count,
                   COUNT(*) FILTER (WHERE EXISTS (
                       SELECT 1 FROM favorites f WHERE f.house_id = houses.id AND f.user_id = %s
                   )) AS favorite_count
            FROM houses WHERE user_id = %s
        """, (user["id"], user["id"])).fetchone()
        version_count = conn.execute("""
            SELECT COUNT(*) AS count FROM house_versions v
            JOIN houses h ON h.id = v.house_id WHERE h.user_id = %s
        """, (user["id"],)).fetchone()["count"]
    return render_template("dashboard.html", user=user, houses=houses, stats=stats, version_count=version_count)


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
            if name.lower().endswith(".json") is False:
                errors.append(f"{name}: only .json house files are supported.")
                continue
            raw = file.read()
            if len(raw) > MAX_HOUSE_BYTES:
                errors.append(f"{name}: file is larger than 10 MB.")
                continue
            content = raw.decode("utf-8", errors="replace")
            ok, error = valid_house_content(content)
            if not ok:
                errors.append(f"{name}: {error}")
                continue
            fc, tc, ht, ambiance = house_metadata(content)
            row = conn.execute("""
                INSERT INTO houses (user_id, name, content, size_bytes, furniture_count, texture_count, house_type, has_ambiance)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (user["id"], name[:255], content, len(raw), fc, tc, ht, ambiance)).fetchone()
            conn.execute("""
                INSERT INTO house_versions (house_id, version_number, content, size_bytes)
                VALUES (%s, 1, %s, %s)
            """, (row["id"], content, len(raw)))
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
        conn.execute("DELETE FROM houses WHERE id = %s AND user_id = %s", (house_id, user["id"]))
    return redirect(url_for("dashboard"))


@app.route("/rename/<int:house_id>", methods=["POST"])
@login_required
def rename_house(house_id):
    user = get_current_user()
    name = request.form.get("name", "").strip()[:255]
    if not name:
        flash("House name cannot be empty.", "error")
        return redirect(url_for("dashboard"))
    with get_db() as conn:
        conn.execute("UPDATE houses SET name = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s AND user_id = %s", (name, house_id, user["id"]))
    flash("House renamed.", "success")
    return redirect(url_for("dashboard"))


@app.route("/favorite/<int:house_id>", methods=["POST"])
@login_required
def favorite_house(house_id):
    user = get_current_user()
    with get_db() as conn:
        owned = conn.execute("SELECT id FROM houses WHERE id = %s AND user_id = %s", (house_id, user["id"])).fetchone()
        if not owned:
            return jsonify({"error": "House not found"}), 404
        existing = conn.execute("SELECT 1 FROM favorites WHERE user_id = %s AND house_id = %s", (user["id"], house_id)).fetchone()
        if existing:
            conn.execute("DELETE FROM favorites WHERE user_id = %s AND house_id = %s", (user["id"], house_id))
            state = False
        else:
            conn.execute("INSERT INTO favorites (user_id, house_id) VALUES (%s, %s)", (user["id"], house_id))
            state = True
    if request.is_json:
        return jsonify({"success": True, "favorite": state})
    return redirect(url_for("dashboard"))


@app.route("/regenerate-token", methods=["POST"])
@login_required
def regenerate_token():
    user = get_current_user()
    token = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute("UPDATE users SET api_token = %s WHERE id = %s", (token, user["id"]))
    flash("API token regenerated. Update the token in your Roblox script.", "success")
    return redirect(url_for("dashboard"))


@app.route("/versions/<int:house_id>")
@login_required
def house_versions_page(house_id):
    user = get_current_user()
    with get_db() as conn:
        rows = conn.execute("""
            SELECT v.id, v.version_number, v.size_bytes, v.created_at
            FROM house_versions v
            JOIN houses h ON h.id = v.house_id
            WHERE v.house_id = %s AND h.user_id = %s
            ORDER BY v.version_number DESC
        """, (house_id, user["id"])).fetchall()
    if not rows:
        return jsonify({"error": "House not found or no versions"}), 404
    return jsonify({"versions": [
        {"id": r["id"], "version": r["version_number"], "size_bytes": r["size_bytes"], "created_at": r["created_at"].isoformat()}
        for r in rows
    ]})


@app.route("/restore/<int:house_id>/<int:version_id>", methods=["POST"])
@login_required
def restore_version(house_id, version_id):
    user = get_current_user()
    with get_db() as conn:
        row = conn.execute("""
            SELECT h.name, v.content
            FROM houses h
            JOIN house_versions v ON v.house_id = h.id
            WHERE h.id = %s AND h.user_id = %s AND v.id = %s
        """, (house_id, user["id"], version_id)).fetchone()
        if not row:
            flash("Version not found.", "error")
            return redirect(url_for("dashboard"))
        fc, tc, ht, ambiance = house_metadata(row["content"])
        latest = conn.execute("SELECT COALESCE(MAX(version_number), 0) AS v FROM house_versions WHERE house_id = %s", (house_id,)).fetchone()["v"]
        new_version = latest + 1
        size = len(row["content"].encode("utf-8"))
        conn.execute("""
            UPDATE houses SET content = %s, size_bytes = %s, furniture_count = %s, texture_count = %s, house_type = %s, has_ambiance = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND user_id = %s
        """, (row["content"], size, fc, tc, ht, ambiance, house_id, user["id"]))
        conn.execute("INSERT INTO house_versions (house_id, version_number, content, size_bytes) VALUES (%s, %s, %s, %s)", (house_id, new_version, row["content"], size))
    flash(f"Restored version and created v{new_version}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/download/<int:house_id>")
@login_required
def download_house(house_id):
    user = get_current_user()
    with get_db() as conn:
        row = conn.execute("SELECT name, content FROM houses WHERE id = %s AND user_id = %s", (house_id, user["id"])).fetchone()
    if not row:
        return "House not found", 404
    filename = row["name"] if row["name"].lower().endswith(".json") else row["name"] + ".json"
    return send_file(BytesIO(row["content"].encode("utf-8")), mimetype="application/json", as_attachment=True, download_name=filename)


# =========================
# Roblox / Cubix API
# =========================

@app.route("/api/me")
def api_me():
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"id": user["id"], "username": user["username"]})


@app.route("/api/houses", methods=["GET"])
def api_list_houses():
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    query = request.args.get("q", "").strip()
    favorites_only = request.args.get("favorites", "0") == "1"
    with get_db() as conn:
        rows = conn.execute("""
            SELECT h.*, EXISTS(
                SELECT 1 FROM favorites f WHERE f.house_id = h.id AND f.user_id = %s
            ) AS favorite
            FROM houses h
            WHERE h.user_id = %s
              AND (%s = '' OR h.name ILIKE %s OR h.house_type ILIKE %s OR h.tags ILIKE %s)
              AND (%s = FALSE OR EXISTS(
                  SELECT 1 FROM favorites f2 WHERE f2.house_id = h.id AND f2.user_id = %s
              ))
            ORDER BY h.updated_at DESC
        """, (user["id"], user["id"], query, f"%{query}%", f"%{query}%", f"%{query}%", favorites_only, user["id"])).fetchall()
    return jsonify({"houses": [serialize_house(row, row["favorite"]) for row in rows]})


@app.route("/api/houses", methods=["POST"])
def api_create_house():
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()[:255]
    # Accept BOTH fields so old and new Cubix scripts remain compatible.
    content = body.get("content")
    if content is None:
        content = body.get("data")
    if not name:
        return jsonify({"error": "name is required"}), 400
    if not isinstance(content, str):
        return jsonify({"error": "content must be a JSON string"}), 400
    ok, error = valid_house_content(content)
    if not ok:
        return jsonify({"error": error}), 400
    fc, tc, ht, ambiance = house_metadata(content)
    with get_db() as conn:
        row = conn.execute("""
            INSERT INTO houses (user_id, name, content, size_bytes, furniture_count, texture_count, house_type, has_ambiance)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (user["id"], name, content, len(content.encode("utf-8")), fc, tc, ht, ambiance)).fetchone()
        conn.execute("INSERT INTO house_versions (house_id, version_number, content, size_bytes) VALUES (%s, 1, %s, %s)", (row["id"], content, len(content.encode("utf-8"))))
    return jsonify({"success": True, "house": serialize_house(row, False), "id": row["id"], "name": row["name"]}), 201


@app.route("/api/houses/<int:house_id>", methods=["GET"])
def api_get_house(house_id):
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        row = conn.execute("""
            SELECT h.*, EXISTS(
                SELECT 1 FROM favorites f WHERE f.house_id = h.id AND f.user_id = %s
            ) AS favorite
            FROM houses h WHERE h.id = %s AND h.user_id = %s
        """, (user["id"], house_id, user["id"])).fetchone()
    if not row:
        return jsonify({"error": "House not found"}), 404
    house = serialize_house(row, row["favorite"], include_content=True)
    # Keep the response shape expected by your existing Lua cloner.
    return jsonify({"id": row["id"], "name": row["name"], "content": row["content"], "data": row["content"], "house": house})


@app.route("/api/houses/<int:house_id>/favorite", methods=["POST"])
def api_favorite_house(house_id):
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        owned = conn.execute("SELECT id FROM houses WHERE id = %s AND user_id = %s", (house_id, user["id"])).fetchone()
        if not owned:
            return jsonify({"error": "House not found"}), 404
        existing = conn.execute("SELECT 1 FROM favorites WHERE user_id = %s AND house_id = %s", (user["id"], house_id)).fetchone()
        if existing:
            conn.execute("DELETE FROM favorites WHERE user_id = %s AND house_id = %s", (user["id"], house_id))
            state = False
        else:
            conn.execute("INSERT INTO favorites (user_id, house_id) VALUES (%s, %s)", (user["id"], house_id))
            state = True
    return jsonify({"success": True, "favorite": state})


@app.route("/api/houses/<int:house_id>", methods=["DELETE"])
def api_delete_house(house_id):
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        result = conn.execute("DELETE FROM houses WHERE id = %s AND user_id = %s RETURNING id", (house_id, user["id"])).fetchone()
    if not result:
        return jsonify({"error": "House not found"}), 404
    return jsonify({"success": True})


@app.route("/api/houses/<int:house_id>/versions", methods=["GET"])
def api_versions(house_id):
    user = bearer_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        owned = conn.execute("SELECT id FROM houses WHERE id = %s AND user_id = %s", (house_id, user["id"])).fetchone()
        if not owned:
            return jsonify({"error": "House not found"}), 404
        rows = conn.execute("SELECT id, version_number, size_bytes, created_at FROM house_versions WHERE house_id = %s ORDER BY version_number DESC", (house_id,)).fetchall()
    return jsonify({"versions": [
        {"id": r["id"], "version": r["version_number"], "size_bytes": r["size_bytes"], "created_at": r["created_at"].isoformat()}
        for r in rows
    ]})


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
