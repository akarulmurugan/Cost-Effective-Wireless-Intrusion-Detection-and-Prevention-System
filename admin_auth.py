#!/usr/bin/env python3
"""
admin_auth.py — WIDS v3.0
Admin two-step login: credentials + OTP.
Single session enforcement with Telegram alerts.
"""
import os, time, secrets, hashlib, threading, sqlite3
from datetime import datetime

ADMIN_USERNAME  = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD  = os.environ.get("ADMIN_PASS", "wids@2025")
SESSION_TIMEOUT = 3600   # 1 hour
OTP_EXPIRY_SEC  = 120    # 2 minutes
LOGIN_OTP_TRIES = 3
LOGIN_LOCKOUT   = 900    # 15 minutes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE  = os.path.join(BASE_DIR, "wids_database.db")

# ── GLOBAL STATE ─────────────────────────────────────────────────
_lock           = threading.Lock()
_active_session = None
_pending_otp    = None
_fail_tracker   = {}

def _hash(pw):
    return hashlib.sha256(f"WIDS_SALT_2025{pw}".encode()).hexdigest()

ADMIN_HASH = _hash(ADMIN_PASSWORD)

def _token():
    return secrets.token_hex(32)

# ── BRUTE FORCE ───────────────────────────────────────────────────
def _check_locked(ip):
    now = time.time()
    with _lock:
        rec = _fail_tracker.get(ip, {})
        if now < rec.get("locked_until", 0):
            return True, int(rec["locked_until"] - now)
    return False, 0

def _fail(ip):
    now = time.time()
    with _lock:
        rec = _fail_tracker.get(ip, {"fails": 0, "locked_until": 0})
        rec["fails"] += 1
        if rec["fails"] >= 5:
            rec["locked_until"] = now + LOGIN_LOCKOUT
            rec["fails"] = 0
        _fail_tracker[ip] = rec
        return rec.get("locked_until", 0) > now

def _clear_fails(ip):
    with _lock:
        _fail_tracker.pop(ip, None)

# ── SESSION ───────────────────────────────────────────────────────
def get_active_session():
    with _lock:
        return dict(_active_session) if _active_session else None

def create_session(ip, ua):
    global _active_session, _pending_otp
    tok = _token()
    now = time.time()
    with _lock:
        if _active_session is not None:
            old_ip = _active_session.get("ip", "unknown")
            old_ts = datetime.fromtimestamp(
                _active_session.get("created", 0)).strftime("%H:%M:%S")
            _active_session = None
            threading.Thread(target=_tg_session_kicked,
                             args=(old_ip, ip, old_ts), daemon=True).start()
            print(f"[AUTH] Kicked old session from {old_ip}")
        _active_session = {
            "token":       tok,
            "ip":          ip,
            "ua":          (ua or "")[:100],
            "created":     now,
            "last_active": now,
        }
        _pending_otp = None
    _log("LOGIN", ip, "Session created")
    threading.Thread(target=_tg_login,
                     args=(ip, datetime.now().strftime("%H:%M:%S")),
                     daemon=True).start()
    return tok

def validate_session(token, ip):
    """
    Validate session token.
    FIXED: reads _active_session into local var 'sess' first.
    No UnboundLocalError possible.
    """
    global _active_session
    if not token:
        return "invalid", "No session token"
    now = time.time()
    with _lock:
        sess = _active_session           # read into local var
        if sess is None:
            return "invalid", "No active session"
        if sess["token"] != token:
            return "invalid", "Invalid session token"
        if now - sess["last_active"] > SESSION_TIMEOUT:
            _active_session = None       # now safe to assign
            return "expired", "Session expired"
        _active_session["last_active"] = now
    return "ok", "Valid"

def destroy_session(token):
    global _active_session
    with _lock:
        sess = _active_session
        if sess and sess.get("token") == token:
            ip = sess.get("ip", "unknown")
            _active_session = None
            threading.Thread(target=_tg_logout,
                             args=(ip,), daemon=True).start()
            _log("LOGOUT", ip, "Manual logout")
            return True
    return False

# ── LOGIN OTP ─────────────────────────────────────────────────────
def create_login_otp(ip, ua):
    global _pending_otp
    import random
    otp  = f"{random.randint(0, 999999):06d}"
    ptok = _token()
    now  = time.time()
    with _lock:
        _pending_otp = {
            "token":   ptok,
            "otp":     otp,
            "ip":      ip,
            "ua":      (ua or "")[:100],
            "created": now,
            "tries":   0,
        }
    # Always print to terminal
    print(f"\n{'='*52}")
    print(f"  [ADMIN LOGIN OTP]")
    print(f"  IP  : {ip}")
    print(f"  OTP : {otp}")
    print(f"  Exp : 2 minutes")
    print(f"{'='*52}\n")
    threading.Thread(target=_tg_login_otp,
                     args=(ip, otp), daemon=True).start()
    _log("OTP_ISSUED", ip, "Login OTP issued")
    return ptok

def verify_login_otp(pending_token, entered_otp, ip):
    global _pending_otp
    entered_otp = str(entered_otp).strip()
    now         = time.time()
    ua          = ""
    with _lock:
        p = _pending_otp
        if p is None:
            return "invalid", "No OTP pending. Please login again."
        if p["token"] != pending_token:
            return "invalid", "Invalid OTP session. Please login again."
        if now - p["created"] > OTP_EXPIRY_SEC:
            _pending_otp = None
            return "expired", "OTP expired. Please login again."
        if now < p.get("locked_until", 0):
            remaining = int(p["locked_until"] - now)
            return "locked", f"Too many attempts. Wait {remaining}s."
        if entered_otp != p["otp"]:
            p["tries"] += 1
            left = LOGIN_OTP_TRIES - p["tries"]
            if p["tries"] >= LOGIN_OTP_TRIES:
                p["locked_until"] = now + LOGIN_LOCKOUT
                threading.Thread(target=_tg_otp_brute,
                                 args=(ip,), daemon=True).start()
                return "locked", f"Too many attempts. Wait {LOGIN_LOCKOUT}s."
            return "wrong", f"Wrong OTP. {left} attempt(s) left."
        ua           = p.get("ua", "")
        _pending_otp = None
    session_tok = create_session(ip, ua)
    _clear_fails(ip)
    _log("OTP_OK", ip, "Login verified")
    return "ok", session_tok

# ── CREDENTIALS ───────────────────────────────────────────────────
def verify_credentials(username, password, ip):
    locked, remaining = _check_locked(ip)
    if locked:
        return "locked", f"Too many attempts. Try again in {remaining}s.", None
    if (username.strip().lower() != ADMIN_USERNAME.lower() or
            _hash(password) != ADMIN_HASH):
        is_locked = _fail(ip)
        if is_locked:
            threading.Thread(target=_tg_brute,
                             args=(ip,), daemon=True).start()
            return "locked", f"Account locked for {LOGIN_LOCKOUT}s.", None
        return "wrong", "Invalid username or password.", None
    try:
        from flask import request as fr
        ua = fr.headers.get("User-Agent", "")
    except Exception:
        ua = ""
    ptok = create_login_otp(ip, ua)
    _log("CRED_OK", ip, f"Credentials verified for {username}")
    return "ok", "OTP sent to admin Telegram.", ptok

# ── DB LOG ────────────────────────────────────────────────────────
def _log(event, ip, detail):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS auth_log("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "event TEXT,ip TEXT,detail TEXT,"
            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
        conn.execute(
            "INSERT INTO auth_log(event,ip,detail) VALUES(?,?,?)",
            (event, ip, detail))
        conn.commit(); conn.close()
    except Exception:
        pass

def get_auth_log(limit=20):
    try:
        conn = sqlite3.connect(DB_FILE)
        rows = conn.execute(
            "SELECT event,ip,detail,timestamp FROM auth_log "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [{"event":r[0],"ip":r[1],"detail":r[2],"time":r[3]}
                for r in rows]
    except Exception:
        return []

# ── TELEGRAM ──────────────────────────────────────────────────────
def _tg_login_otp(ip, otp):
    try:
        from telegram_alerts import notify_login_otp
        notify_login_otp(ip, otp)
    except Exception as e: print(f"[AUTH-TG] {e}")

def _tg_login(ip, ts):
    try:
        from telegram_alerts import notify_admin_login
        notify_admin_login(ip, ts)
    except Exception as e: print(f"[AUTH-TG] {e}")

def _tg_logout(ip):
    try:
        from telegram_alerts import notify_admin_logout
        notify_admin_logout(ip)
    except Exception as e: print(f"[AUTH-TG] {e}")

def _tg_session_kicked(old_ip, new_ip, old_ts):
    try:
        from telegram_alerts import notify_session_kicked
        notify_session_kicked(old_ip, new_ip, old_ts)
    except Exception as e: print(f"[AUTH-TG] {e}")

def _tg_brute(ip):
    try:
        from telegram_alerts import notify_brute_force
        notify_brute_force(ip)
    except Exception as e: print(f"[AUTH-TG] {e}")

def _tg_otp_brute(ip):
    try:
        from telegram_alerts import notify_otp_brute_admin
        notify_otp_brute_admin(ip)
    except Exception as e: print(f"[AUTH-TG] {e}")

# ── CLEANUP ───────────────────────────────────────────────────────
def _cleanup():
    global _active_session, _pending_otp
    while True:
        now = time.time()
        with _lock:
            if _active_session is not None:
                if now - _active_session["last_active"] > SESSION_TIMEOUT:
                    ip = _active_session.get("ip", "unknown")
                    _active_session = None
                    print(f"[AUTH] Session expired (inactivity): {ip}")
            if _pending_otp is not None:
                if now - _pending_otp["created"] > OTP_EXPIRY_SEC * 2:
                    _pending_otp = None
        time.sleep(30)

threading.Thread(target=_cleanup, daemon=True).start()
