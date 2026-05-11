
from datetime import datetime
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import time

from flask import Flask, abort, request, session, redirect, url_for, render_template, jsonify
import mysql.connector
from werkzeug.security import check_password_hash


def load_env_file():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        return

    with open(env_path, encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


load_env_file()

app = Flask(__name__)


def required_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return value


app.secret_key = required_env("FLASK_SECRET_KEY")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
)

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "192.168.2.200"),
    "user": os.environ.get("DB_USER", "webuser"),
    "password": required_env("DB_PASSWORD"),
    "database": os.environ.get("DB_NAME", "login_db"),
    "autocommit": True
}

MAX_FAILED_COUNT = 10
LOCK_MINUTES = 15
IP_WINDOW_MINUTES = 10
IP_MAX_FAILS = 20
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() == "true"
TRUSTED_PROXY_IPS = {
    ip.strip()
    for ip in os.environ.get("TRUSTED_PROXY_IPS", "192.168.2.1,127.0.0.1,::1").split(",")
    if ip.strip()
}


def get_db():
    return mysql.connector.connect(**DB_CONFIG)


def limit_text(value, max_length):
    if value is None:
        return None
    return str(value)[:max_length]


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_client_ip():
    remote_addr = request.remote_addr or "unknown"
    xff = request.headers.get("X-Forwarded-For", "")

    if TRUST_PROXY_HEADERS and remote_addr in TRUSTED_PROXY_IPS and xff:
        forwarded_ip = xff.split(",")[0].strip()
        if is_valid_ip(forwarded_ip):
            return forwarded_ip

    return remote_addr


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token():
    expected = session.get("_csrf_token")
    supplied = (
        request.form.get("_csrf_token")
        or request.headers.get("X-CSRF-Token")
        or (request.get_json(silent=True) or {}).get("csrf_token")
    )
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    )
    return response


def detect_sqli(input_text):
    if not input_text:
        return False

    patterns = [
        r"(?i)\bor\b\s+1=1",
        r"(?i)'\s*or\s*'1'\s*=\s*'1",
        r"(?i)'\s*or\s*1=1\s*--",
        r"(?i)union\s+select",
        r"(?i)drop\s+table",
        r"(?i)insert\s+into",
        r"(?i)delete\s+from",
        r"(?i)update\s+\w+\s+set",
        r"(?i)--",
        r"(?i)#",
        r"(?i)/\*.*\*/"
    ]

    for pattern in patterns:
        if re.search(pattern, input_text):
            return True
    return False


def log_login_attempt(username, success, client_ip, reason=""):
    username = limit_text(username, 50)
    client_ip = limit_text(client_ip, 45)
    reason = limit_text(reason, 64)

    log_security_event(username, success, client_ip, reason)
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO login_logs (input_id, success, client_ip, reason, created_at)
            VALUES (%s, %s, %s, %s, NOW())
            """,
            (username, 1 if success else 0, client_ip, reason)
        )
    except mysql.connector.Error:
        app.logger.exception("failed to write login attempt to database")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def log_security_event(username, success, client_ip, reason):
    severity = "info" if success else "medium"
    if reason in {"sqli_attempt", "ip_rate_limited", "account_locked_after_fail"}:
        severity = "high"
    elif reason.startswith("forbidden") or reason.startswith("unauthorized"):
        severity = "medium"

    event = {
        "event_type": "web_login",
        "event_category": "authentication",
        "outcome": "success" if success else "failure",
        "severity": severity,
        "src_ip": client_ip,
        "user": username,
        "reason": reason,
        "path": request.path,
        "method": request.method,
        "user_agent": request.headers.get("User-Agent", ""),
    }
    app.logger.info(json.dumps(event, ensure_ascii=False))


def get_recent_failed_count_by_ip(client_ip):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM login_logs
            WHERE client_ip = %s
              AND success = 0
              AND created_at >= (NOW() - INTERVAL %s MINUTE)
            """,
            (client_ip, IP_WINDOW_MINUTES)
        )
        row = cur.fetchone()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return row["cnt"] if row else 0


def get_user_by_username(username):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, username, password_hash, role, failed_count, locked_until
            FROM users
            WHERE username = %s
            """,
            (username,)
        )
        user = cur.fetchone()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return user


def get_user_role_by_id(user_id):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return user["role"] if user else None


def reset_user_fail_state(user_id):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE users
            SET failed_count = 0,
                locked_until = NULL
            WHERE id = %s
            """,
            (user_id,)
        )
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def register_user_fail(user_id):
    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            UPDATE users
            SET failed_count = failed_count + 1,
                locked_until = CASE
                    WHEN failed_count + 1 >= %s THEN DATE_ADD(NOW(), INTERVAL %s MINUTE)
                    ELSE locked_until
                END
            WHERE id = %s
            """,
            (MAX_FAILED_COUNT, LOCK_MINUTES, user_id)
        )
        cur.execute("SELECT failed_count FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        failed_count = row["failed_count"] if row else 0
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return failed_count


def is_logged_in():
    return "user_id" in session


def is_admin():
    if session.get("role") != "admin" or not session.get("user_id"):
        return False

    try:
        return get_user_role_by_id(session["user_id"]) == "admin"
    except mysql.connector.Error:
        app.logger.exception("failed to verify admin role")
        return False


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/csrf-token", methods=["GET"])
def csrf_token_api():
    return jsonify({"csrf_token": get_csrf_token()})


@app.route("/login", methods=["POST"])
def login():
    client_ip = get_client_ip()
    payload = request.get_json(silent=True) if request.is_json else None
    username = ((payload or {}).get("id") or (payload or {}).get("username") or request.form.get("id") or request.form.get("username") or "").strip()
    password = ((payload or {}).get("pw") or (payload or {}).get("password") or request.form.get("pw") or request.form.get("password") or "").strip()
    wants_json = request.is_json or "application/json" in request.headers.get("Accept", "")

    if not validate_csrf_token():
        log_login_attempt(username if username else "unknown", False, client_ip, reason="csrf_failed")
        time.sleep(0.5)
        return jsonify({"message": "로그인에 실패했습니다."}), 400

    # SQL Injection 시도 탐지
    if detect_sqli(username) or detect_sqli(password):
        log_login_attempt(username if username else "unknown", False, client_ip, reason="sqli_attempt")
        time.sleep(0.8)
        return jsonify({"message": "로그인에 실패했습니다."}), 400

    # IP 기준 추가 제한
    recent_ip_fails = get_recent_failed_count_by_ip(client_ip)
    if recent_ip_fails >= IP_MAX_FAILS:
        log_login_attempt(username if username else "unknown", False, client_ip, reason="ip_rate_limited")
        time.sleep(1.0)
        return jsonify({"message": "로그인에 실패했습니다."}), 429

    user = get_user_by_username(username)

    # 존재하지 않는 계정도 동일한 메시지
    if not user:
        log_login_attempt(username if username else "unknown", False, client_ip, reason="unknown_user")
        time.sleep(0.8)
        return jsonify({"message": "로그인에 실패했습니다."}), 401

    # 계정 잠금 여부 체크
    locked_until = user["locked_until"]
    if locked_until and locked_until > datetime.now():
        log_login_attempt(username, False, client_ip, reason="account_locked")
        time.sleep(1.0)
        return jsonify({"message": "로그인에 실패했습니다."}), 423

    # 비밀번호 검증
    if check_password_hash(user["password_hash"], password):
        reset_user_fail_state(user["id"])
        log_login_attempt(username, True, client_ip, reason="login_success")

        session.clear()
        get_csrf_token()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["client_ip"] = client_ip

        next_url = url_for("admin") if user["role"] == "admin" else url_for("dashboard")
        if wants_json:
            return jsonify({"message": "로그인에 성공했습니다.", "next": next_url})
        if user["role"] == "admin":
            return redirect(url_for("admin"))
        return redirect(url_for("dashboard"))

    # 실패 처리
    failed_count = register_user_fail(user["id"])

    if failed_count >= MAX_FAILED_COUNT:
        log_login_attempt(username, False, client_ip, reason="account_locked_after_fail")
    else:
        log_login_attempt(username, False, client_ip, reason="bad_password")

    time.sleep(0.8)
    return jsonify({"message": "로그인에 실패했습니다."}), 401


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not is_logged_in():
        return redirect(url_for("index"))

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        client_ip=session.get("client_ip")
    )


@app.route("/admin", methods=["GET"])
def admin():
    if not is_logged_in():
        log_login_attempt("unknown", False, get_client_ip(), reason="unauthorized_admin_access")
        return redirect(url_for("index"))

    if not is_admin():
        log_login_attempt(session.get("username", "unknown"), False, get_client_ip(), reason="forbidden_admin_access")
        return jsonify({"message": "접근 권한이 없습니다."}), 403

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT
                COUNT(*) AS total_attempts,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS success_count,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS fail_count
            FROM login_logs
            """
        )
        stats = cur.fetchone()

        cur.execute(
            """
            SELECT input_id, success, client_ip, reason, created_at
            FROM login_logs
            ORDER BY created_at DESC
            LIMIT 20
            """
        )
        recent_logs = cur.fetchall()

        cur.execute(
            """
            SELECT client_ip, COUNT(*) AS fail_count
            FROM login_logs
            WHERE success = 0
            GROUP BY client_ip
            ORDER BY fail_count DESC
            LIMIT 10
            """
        )
        top_attack_ips = cur.fetchall()

        cur.execute(
            """
            SELECT username, failed_count, locked_until
            FROM users
            WHERE locked_until IS NOT NULL
              AND locked_until > NOW()
            ORDER BY locked_until DESC
            """
        )
        locked_users = cur.fetchall()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return render_template(
        "admin.html",
        username=session.get("username"),
        stats=stats,
        recent_logs=recent_logs,
        top_attack_ips=top_attack_ips,
        locked_users=locked_users
    )


@app.route("/logs", methods=["GET"])
def logs():
    if not is_logged_in():
        return redirect(url_for("index"))

    if not is_admin():
        log_login_attempt(session.get("username", "unknown"), False, get_client_ip(), reason="forbidden_logs_access")
        return jsonify({"message": "접근 권한이 없습니다."}), 403

    status_filter = request.args.get("status", "").strip()
    reason_filter = request.args.get("reason", "").strip()
    ip_filter = request.args.get("ip", "").strip()

    query = """
        SELECT input_id, success, client_ip, reason, created_at
        FROM login_logs
        WHERE 1=1
    """
    params = []

    if status_filter == "success":
        query += " AND success = 1"
    elif status_filter == "fail":
        query += " AND success = 0"

    if reason_filter:
        query += " AND reason = %s"
        params.append(reason_filter)

    if ip_filter:
        query += " AND client_ip = %s"
        params.append(ip_filter)

    query += " ORDER BY created_at DESC LIMIT 200"

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute(query, tuple(params))
        logs = cur.fetchall()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return render_template(
        "logs.html",
        logs=logs,
        status_filter=status_filter,
        reason_filter=reason_filter,
        ip_filter=ip_filter
    )


@app.route("/admin/users", methods=["GET"])
def admin_users():
    if not is_logged_in():
        return redirect(url_for("index"))

    if not is_admin():
        log_login_attempt(session.get("username", "unknown"), False, get_client_ip(), reason="forbidden_user_admin_access")
        return jsonify({"message": "접근 권한이 없습니다."}), 403

    conn = None
    cur = None
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, username, role, failed_count, locked_until
            FROM users
            ORDER BY id ASC
            """
        )
        users = cur.fetchall()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return render_template(
        "admin_users.html",
        users=users,
        username=session.get("username")
    )


@app.route("/admin/unlock/<int:user_id>", methods=["POST"])
def unlock_user(user_id):
    if not is_logged_in():
        return redirect(url_for("index"))

    if not is_admin():
        log_login_attempt(session.get("username", "unknown"), False, get_client_ip(), reason="forbidden_unlock_access")
        return jsonify({"message": "접근 권한이 없습니다."}), 403

    if not validate_csrf_token():
        log_login_attempt(session.get("username", "unknown"), False, get_client_ip(), reason="csrf_failed_unlock")
        return jsonify({"message": "잘못된 요청입니다."}), 400

    reset_user_fail_state(user_id)
    return redirect(url_for("admin_users"))


@app.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf_token():
        return jsonify({"message": "잘못된 요청입니다."}), 400
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
