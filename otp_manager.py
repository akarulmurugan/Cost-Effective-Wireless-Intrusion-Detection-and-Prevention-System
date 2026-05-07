#!/usr/bin/env python3
"""
otp_manager.py — WIDS v3.0

CRITICAL DESIGN:
  - OTP is NEVER automatically issued when device connects
  - Admin manually sends OTP from dashboard (/api/send_otp/<mac>)
  - Device shows "Request OTP" button → notifies admin via Telegram
  - Admin decides whether to send OTP or block
  - OTP deleted immediately after correct entry (no reuse)
  - Pressing back and resubmitting → "not_found" error
"""
import random, time, threading

OTP_EXPIRY_SEC  = 300   # 5 minutes
OTP_MAX_TRIES   = 3
OTP_LOCKOUT_SEC = 600   # 10 minutes

_lock = threading.Lock()
_otps = {}              # mac → otp record
_requests = {}          # mac → request timestamp (device requested OTP)

def _gen():
    return f"{random.randint(0, 999999):06d}"

# ── Device requests OTP (does NOT send it — just notifies admin) ──
def request_otp(mac, ip):
    """
    Called when device taps "Request OTP" on captive portal.
    Does NOT generate or send OTP.
    Just records the request and notifies admin via Telegram.
    Admin then decides to send OTP using send_otp_to_device().
    """
    now = time.time()
    with _lock:
        last = _requests.get(mac, 0)
        if now - last < 30:   # 30s cooldown between requests
            return False, "Please wait 30 seconds before requesting again."
        _requests[mac] = now

    # Notify admin
    try:
        from telegram_alerts import notify_otp_request
        notify_otp_request(mac, ip)
    except Exception as e:
        print(f"[OTP-REQUEST] Telegram notify failed: {e}")

    print(f"[OTP] Request received from {mac} @ {ip} — awaiting admin action")
    return True, "OTP request sent to administrator. Please wait."

# ── Admin manually sends OTP ──────────────────────────────────────
def send_otp_to_device(mac, ip):
    """
    Called by admin from dashboard → /api/send_otp/<mac>
    Generates OTP and sends it to admin Telegram.
    Admin then verbally gives OTP to device user.
    """
    otp = _gen()
    now = time.time()
    with _lock:
        _otps[mac] = {
            "otp":          otp,
            "ip":           ip,
            "created":      now,
            "tries":        0,
            "locked_until": 0,
        }
        _requests.pop(mac, None)   # clear request

    # Always print to terminal (backup if Telegram fails)
    print(f"\n{'='*52}")
    print(f"  [DEVICE OTP — ADMIN SENT]")
    print(f"  MAC : {mac}")
    print(f"  IP  : {ip}")
    print(f"  OTP : {otp}")
    print(f"  Exp : 5 minutes")
    print(f"{'='*52}\n")

    try:
        from telegram_alerts import alert_otp_issued
        alert_otp_issued(mac, ip, otp)
    except Exception as e:
        print(f"[OTP] Telegram failed: {e}")

    return otp

def get_pending_requests():
    """Return list of devices that have requested OTP but not received one."""
    now = time.time()
    with _lock:
        result = []
        for mac, ts in _requests.items():
            if now - ts < 300:   # requests expire after 5 minutes
                result.append({"mac": mac, "requested_at": ts,
                               "seconds_ago": int(now - ts)})
        return result

# ── Validate OTP ──────────────────────────────────────────────────
def validate_otp(mac, entered):
    """
    Returns ("ok"|"wrong"|"expired"|"locked"|"not_found", detail)
    On "ok" → detail = ip address.
    Record DELETED immediately after correct entry — no reuse.
    """
    entered = str(entered).strip()
    now     = time.time()

    with _lock:
        r = _otps.get(mac)

        if r is None:
            return ("not_found",
                    "No OTP found for this device. "
                    "Click 'Request OTP' and wait for admin approval.")

        if now < r["locked_until"]:
            remaining = int(r["locked_until"] - now)
            return ("locked",
                    f"Too many wrong attempts. "
                    f"Try again in {remaining}s.")

        if now - r["created"] > OTP_EXPIRY_SEC:
            del _otps[mac]
            return ("expired",
                    "OTP expired (5 minutes). "
                    "Click 'Request OTP' again.")

        if entered != r["otp"]:
            r["tries"] += 1
            left = OTP_MAX_TRIES - r["tries"]
            if r["tries"] >= OTP_MAX_TRIES:
                r["locked_until"] = now + OTP_LOCKOUT_SEC
                try:
                    from telegram_alerts import alert_otp_brute
                    alert_otp_brute(mac, r["ip"])
                except Exception:
                    pass
                return ("locked",
                        f"Too many wrong attempts. "
                        f"Locked for {OTP_LOCKOUT_SEC}s.")
            return ("wrong", f"Wrong OTP. {left} attempt(s) left.")

        # ✅ CORRECT — delete immediately, no reuse
        ip = r["ip"]
        del _otps[mac]

    print(f"[OTP] ✅ Correct for {mac} — deleted (no reuse possible)")
    return ("ok", ip)

def get_otp_status(mac):
    """Return OTP status for captive portal timer."""
    now = time.time()
    with _lock:
        # Check if request is pending (no OTP sent yet)
        req_ts = _requests.get(mac)
        r      = _otps.get(mac)

        if r is None and req_ts:
            return {"status": "requested",
                    "seconds_ago": int(now - req_ts)}
        if r is None:
            return {"status": "none"}
        if now < r["locked_until"]:
            return {"status": "locked",
                    "remaining": int(r["locked_until"] - now)}
        if now - r["created"] > OTP_EXPIRY_SEC:
            return {"status": "expired"}
        return {"status": "pending",
                "remaining": int(OTP_EXPIRY_SEC - (now - r["created"])),
                "tries": r["tries"]}

def revoke_otp(mac):
    with _lock:
        _otps.pop(mac, None)
        _requests.pop(mac, None)

def has_pending_otp(mac):
    now = time.time()
    with _lock:
        r = _otps.get(mac)
        if not r: return False
        return now - r["created"] <= OTP_EXPIRY_SEC

def _cleanup():
    while True:
        now = time.time()
        with _lock:
            expired_otps = [m for m, r in _otps.items()
                            if now - r["created"] > OTP_EXPIRY_SEC * 3]
            for m in expired_otps: del _otps[m]
            expired_reqs = [m for m, ts in _requests.items()
                            if now - ts > 300]
            for m in expired_reqs: del _requests[m]
        time.sleep(60)

threading.Thread(target=_cleanup, daemon=True).start()
