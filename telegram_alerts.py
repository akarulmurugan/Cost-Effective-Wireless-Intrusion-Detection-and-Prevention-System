#!/usr/bin/env python3
"""telegram_alerts.py — WIDS v3.0 push notifications."""
import os, time, threading, requests

TOKEN   = os.environ.get("TG_TOKEN",   "YOUR_BOT_TOKEN")
CHAT_ID = os.environ.get("TG_CHAT_ID", "YOUR_CHAT_ID")
API     = f"https://api.telegram.org/bot{TOKEN}"

_cd  = {}
_CDS = 30  # cooldown per MAC

def _on_cd(mac):
    now = time.time()
    if now - _cd.get(mac, 0) < _CDS: return True
    _cd[mac] = now
    return False

def _send(text):
    """Send Telegram message. Always prints to terminal as backup."""
    print(f"\n[TELEGRAM]\n{text}\n")
    try:
        r = requests.post(
            f"{API}/sendMessage",
            json={"chat_id": CHAT_ID, "text": text,
                  "parse_mode": "Markdown"},
            timeout=8)
        if not r.ok:
            print(f"[TG] Error: {r.status_code} {r.text[:100]}")
    except Exception as e:
        print(f"[TG] Failed: {e}")

def _bg(text):
    threading.Thread(target=_send, args=(text,), daemon=True).start()

# ── Device alerts ────────────────────────────────────────────────
def alert_intruder(mac, ip, reason):
    """Called when unauthorized device detected — does NOT send OTP."""
    if _on_cd(mac): return
    _bg(f"🚨 *WIDS — Unauthorized Device Detected*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 MAC: `{mac}`\n"
        f"🌐 IP:  `{ip}`\n"
        f"⚠️ {reason}\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🛡 Captive portal active\n"
        f"📲 Device will request OTP manually\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

def notify_otp_request(mac, ip):
    """
    Called when device taps 'Request OTP' on captive portal.
    Notifies admin to manually send OTP from dashboard.
    Does NOT include the OTP — admin must go to dashboard to send it.
    """
    _bg(f"📲 *WIDS — OTP Request from Device*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 MAC: `{mac}`\n"
        f"🌐 IP:  `{ip}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Device is requesting network access.\n"
        f"👉 Go to dashboard and click *SEND OTP*\n"
        f"   if you recognize this device.\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

def alert_otp_issued(mac, ip, otp):
    """Called when admin manually sends OTP from dashboard."""
    _bg(f"🔐 *WIDS — OTP Sent to Device*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 MAC: `{mac}`\n"
        f"🌐 IP:  `{ip}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔑 *OTP: `{otp}`*\n"
        f"⏱ Expires in 5 minutes\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"Share this OTP only with the device user.")

def alert_otp_brute(mac, ip):
    _bg(f"🚨 *WIDS — OTP Brute Force*\n"
        f"MAC: `{mac}` IP: `{ip}`\n"
        f"3 wrong OTP attempts — locked 10 min\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

def alert_authorized(mac):
    _bg(f"✅ *WIDS — Device Authorized*\n"
        f"`{mac}` — internet access granted\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

def alert_flood(n, w):
    _bg(f"🔴 *WIDS — MAC Flood / DHCP Starvation*\n"
        f"{n} unique MACs in {w}s\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

def alert_cert_issued(mac, ip, cid):
    _bg(f"📜 *WIDS — Certificate Issued*\n"
        f"MAC: `{mac}` IP: `{ip}`\n"
        f"ID: `{cid}`\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

def alert_startup(ssid, iface):
    _bg(f"🟢 *WIDS v3.0 Online*\n"
        f"📶 `{ssid}`\n"
        f"🔌 `{iface}`\n"
        f"🛡 Manual OTP mode active\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

# ── Admin login alerts ────────────────────────────────────────────
def notify_login_otp(ip, otp):
    _bg(f"🔐 *WIDS Admin Login OTP*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 IP: `{ip}`\n"
        f"🔑 *OTP: `{otp}`*\n"
        f"⏱ Expires in 2 minutes\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"If this was not you — someone has your password!")

def notify_admin_login(ip, ts):
    _bg(f"✅ *WIDS Admin — Login Successful*\n"
        f"🌐 IP: `{ip}`\n⏱ {ts}")

def notify_admin_logout(ip):
    _bg(f"🔓 *WIDS Admin — Logged Out*\n"
        f"🌐 IP: `{ip}`\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

def notify_session_kicked(old_ip, new_ip, old_ts):
    _bg(f"⚠️ *WIDS Admin — Session Kicked*\n"
        f"❌ Old session: `{old_ip}` (started {old_ts})\n"
        f"🆕 New login:   `{new_ip}`\n"
        f"Check immediately if old session was you!")

def notify_brute_force(ip):
    _bg(f"🚨 *WIDS Admin — Brute Force*\n"
        f"🌐 IP: `{ip}`\n"
        f"5 failed login attempts — locked 15 min\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

def notify_otp_brute_admin(ip):
    _bg(f"🚨 *WIDS Admin — Login OTP Brute Force*\n"
        f"🌐 IP: `{ip}`\n"
        f"3 wrong OTP attempts — locked 15 min\n"
        f"⏱ {time.strftime('%H:%M:%S')}")

if __name__ == "__main__":
    print("Sending test message...")
    _send("✅ WIDS Telegram bot connected!")
    print("Check your Telegram.")
