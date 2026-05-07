#!/usr/bin/env python3
"""
captive_portal.py — WIDS v3.0

COMPLETE BLACKHOLE — blocks ALL protocols:
  IPv4 TCP  → BLOCKED (web, email, SSH)
  IPv4 UDP  → BLOCKED (games, QUIC, DNS, NTP)
  IPv4 ICMP → BLOCKED (ping)
  IPv6 ALL  → BLOCKED (YouTube QUIC, Instagram, any IPv6 app)
  UDP 443   → BLOCKED (QUIC/HTTP3 — used by YouTube, Instagram)
  UDP 80    → BLOCKED (some CDNs)

Only port 8000 TCP allowed → captive portal page.
Port 80 TCP → redirected to captive portal.

Mobile popup:
  iOS    → probes captive.apple.com/hotspot-detect.html → we return 302
  Android → probes connectivitycheck.gstatic.com/generate_204 → we return 302
  Both OS show "Sign in to network" popup automatically.
"""
from flask import (Blueprint, request, jsonify,
                   render_template_string, send_file,
                   redirect, make_response)
import subprocess, os, threading, time

captive_bp = Blueprint('captive', __name__)

YOUR_SSID     = "Airtel_Zerotouch-2"
WIFI_PASSWORD = ""
L3_INTERFACE  = "eth0"
CERT_DIR      = "certs"
SERVER_IP     = "192.168.1.3"

_approved_macs = set()
_approved_lock = threading.Lock()

def mark_mac_approved(mac):
    with _approved_lock:
        _approved_macs.add(mac.upper())

def is_mac_approved(mac):
    with _approved_lock:
        return mac.upper() in _approved_macs

# ══════════════════════════════════════════════════════════════════
# COMPLETE BLACKHOLE — ALL PROTOCOLS BLOCKED
# This is the core fix: previous version only blocked TCP FORWARD.
# YouTube/Instagram use QUIC (UDP 443). Games use UDP.
# IPv6 traffic completely bypassed IPv4 rules.
# ══════════════════════════════════════════════════════════════════
def apply_strict_captive_rules(target_ip):
    """
    Block ALL traffic from/to this device.

    Rules applied:
    1. DROP all FORWARD from this IP (blocks internet — TCP, UDP, ALL)
    2. DROP all FORWARD to this IP (blocks scan results returning)
    3. DROP UDP port 443 INPUT (QUIC/HTTP3 — YouTube, Instagram, Chrome)
    4. DROP UDP port 80 INPUT (some CDNs use UDP 80)
    5. DROP ALL UDP INPUT from this IP (games, DNS, NTP, all UDP apps)
    6. DROP DNS INPUT (53 TCP+UDP)
    7. DROP ICMP INPUT (ping)
    8. ACCEPT port 8000 TCP INPUT (captive portal only)
    9. NAT REDIRECT port 80 TCP → port 8000 (captive portal trigger)
    10. NAT REDIRECT port 443 TCP → port 8000 (HTTPS captive trigger)

    IPv6 is handled separately in server.py via ip6tables.
    """

    # ── Core: block ALL forwarding ────────────────────────────────
    # This blocks TCP, UDP, ICMP, everything in the FORWARD chain
    rules_v4 = [
        # Block ALL internet traffic (TCP, UDP, ICMP, everything)
        ["sudo","iptables","-I","FORWARD","-s",target_ip,"-j","DROP"],
        ["sudo","iptables","-I","FORWARD","-d",target_ip,"-j","DROP"],

        # Block ALL UDP from this device to our machine
        # (covers QUIC/HTTP3 port 443, games, DNS, NTP, etc.)
        ["sudo","iptables","-I","INPUT","-s",target_ip,"-p","udp","-j","DROP"],

        # Block ALL TCP from this device to our machine (except 8000)
        ["sudo","iptables","-I","INPUT","-s",target_ip,"-p","tcp",
         "--dport","0:7999","-j","DROP"],
        ["sudo","iptables","-I","INPUT","-s",target_ip,"-p","tcp",
         "--dport","8001:65535","-j","DROP"],

        # Block ICMP (ping)
        ["sudo","iptables","-I","INPUT","-s",target_ip,"-p","icmp","-j","DROP"],

        # Allow ONLY captive portal port 8000
        ["sudo","iptables","-I","INPUT","-s",target_ip,"-p","tcp",
         "--dport","8000","-j","ACCEPT"],

        # Redirect HTTP port 80 → captive portal (triggers iOS/Android popup)
        ["sudo","iptables","-t","nat","-I","PREROUTING",
         "-s",target_ip,"-p","tcp","--dport","80",
         "-j","REDIRECT","--to-port","8000"],

        # Redirect HTTPS port 443 TCP → captive portal
        # This makes HTTPS sites also redirect to captive portal
        # instead of giving SSL errors
        ["sudo","iptables","-t","nat","-I","PREROUTING",
         "-s",target_ip,"-p","tcp","--dport","443",
         "-j","REDIRECT","--to-port","8000"],
    ]

    for r in rules_v4:
        subprocess.run(r, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Re-protect own machine after adding rules
    subprocess.run(["sudo","iptables","-I","OUTPUT","-j","ACCEPT"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo","iptables","-I","INPUT","-m","state",
                    "--state","ESTABLISHED,RELATED","-j","ACCEPT"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"[CAPTIVE] ✅ Full blackhole applied → {target_ip}")
    print(f"[CAPTIVE]    IPv4 TCP/UDP/ICMP ALL blocked")
    print(f"[CAPTIVE]    QUIC/HTTP3 (UDP 443) blocked")
    print(f"[CAPTIVE]    Port 80+443 redirected to captive portal")

def remove_strict_captive_rules(target_ip):
    """Remove all captive restrictions — called after OTP validated."""
    rules_v4 = [
        ["sudo","iptables","-D","FORWARD","-s",target_ip,"-j","DROP"],
        ["sudo","iptables","-D","FORWARD","-d",target_ip,"-j","DROP"],
        ["sudo","iptables","-D","INPUT","-s",target_ip,"-p","udp","-j","DROP"],
        ["sudo","iptables","-D","INPUT","-s",target_ip,"-p","tcp",
         "--dport","0:7999","-j","DROP"],
        ["sudo","iptables","-D","INPUT","-s",target_ip,"-p","tcp",
         "--dport","8001:65535","-j","DROP"],
        ["sudo","iptables","-D","INPUT","-s",target_ip,"-p","icmp","-j","DROP"],
        ["sudo","iptables","-D","INPUT","-s",target_ip,"-p","tcp",
         "--dport","8000","-j","ACCEPT"],
        ["sudo","iptables","-t","nat","-D","PREROUTING",
         "-s",target_ip,"-p","tcp","--dport","80",
         "-j","REDIRECT","--to-port","8000"],
        ["sudo","iptables","-t","nat","-D","PREROUTING",
         "-s",target_ip,"-p","tcp","--dport","443",
         "-j","REDIRECT","--to-port","8000"],
    ]
    for r in rules_v4:
        subprocess.run(r, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with _approved_lock:
        _approved_macs.discard(target_ip)
    print(f"[CAPTIVE] ✅ Rules removed → {target_ip} (internet restored)")

# ══════════════════════════════════════════════════════════════════
# OS CAPTIVE PORTAL DETECTION
#
# How mobile popup works:
#   iOS:     background service calls captive.apple.com/hotspot-detect.html
#            expects: <HTML><BODY>Success</BODY></HTML>
#            we return: 302 redirect → /captive
#            iOS sees wrong response → shows "Sign in to Airtel" popup ✅
#
#   Android: background service calls connectivitycheck.gstatic.com/generate_204
#            expects: HTTP 204 No Content
#            we return: 302 redirect → /captive
#            Android sees wrong response → shows "Sign in to network" notification ✅
#
# Our iptables redirects port 80 from the device to our port 8000.
# So when iOS calls captive.apple.com it actually hits OUR server.
# We return a redirect → iOS shows the popup automatically.
# ══════════════════════════════════════════════════════════════════

def _portal_redirect():
    server_ip = _get_server_ip()
    url = f"http://{server_ip}:8000/captive"
    resp = make_response(redirect(url, code=302))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma']        = 'no-cache'
    resp.headers['Expires']       = '0'
    return resp

# iOS detection URLs
@captive_bp.route('/hotspot-detect.html')
@captive_bp.route('/library/test/success.html')
@captive_bp.route('/bag')
# Android detection URLs
@captive_bp.route('/generate_204')
@captive_bp.route('/gen_204')
@captive_bp.route('/connecttest.txt')
@captive_bp.route('/redirect')
@captive_bp.route('/success.txt')
@captive_bp.route('/mobile/status.php')
# Windows detection URLs
@captive_bp.route('/ncsi.txt')
@captive_bp.route('/canonical.html')
# Samsung/Huawei Android variants
@captive_bp.route('/generate204')
@captive_bp.route('/check_network_status.txt')
def captive_detect():
    """
    Return 302 redirect to our captive portal page.
    This triggers the OS-native 'Sign in to network' popup
    within 3-5 seconds of the device associating with the AP.
    """
    return _portal_redirect()

# ── Helpers ───────────────────────────────────────────────────────
def _ip_to_mac(ip):
    try:
        out = subprocess.check_output(
            ["arp","-n"], stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            if line.startswith(ip):
                parts = line.split()
                if len(parts) >= 3 and ':' in parts[2]:
                    return parts[2].upper()
    except Exception:
        pass
    return None

def _mac_to_ip(mac):
    try:
        out = subprocess.check_output(
            ["arp","-n"], stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2].upper() == mac.upper():
                return parts[0]
    except Exception:
        pass
    return None

def _get_server_ip():
    if SERVER_IP and SERVER_IP not in ("0.0.0.0","",None):
        return SERVER_IP
    try:
        out = subprocess.check_output(
            ["ip","addr","show",L3_INTERFACE],
            stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            if "inet " in line:
                return line.strip().split()[1].split('/')[0]
    except Exception:
        pass
    return "192.168.1.3"

# ══════════════════════════════════════════════════════════════════
# CAPTIVE PORTAL PAGE
# ══════════════════════════════════════════════════════════════════
PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta http-equiv="Cache-Control" content="no-cache,no-store,must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<title>Network Access — {{ ssid }}</title>
<style>
:root{
  --bg:#030810;--card:#060f1e;
  --cyan:#00ffe0;--cyan2:#00bfaa;
  --green:#00ff88;--red:#ff2244;
  --amber:#ffaa00;--purple:#a78bfa;
  --text:#c8e8f0;--muted:#4a7a8a;
  --border:rgba(0,255,224,0.15);
  --mono:'Courier New',monospace;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);
  min-height:100vh;display:flex;align-items:center;
  justify-content:center;padding:16px;}
body::before{content:'';position:fixed;inset:0;pointer-events:none;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,
  rgba(0,0,0,0.07) 2px,rgba(0,0,0,0.07) 4px);}
.card{background:var(--card);border:1px solid var(--border);
  border-radius:14px;max-width:400px;width:100%;
  padding:26px 22px;position:relative;z-index:1;}

.shield{text-align:center;margin-bottom:12px;}
.shield svg{width:44px;height:44px;
  filter:drop-shadow(0 0 10px rgba(0,255,224,.4));}
h1{font-size:14px;letter-spacing:2px;color:var(--cyan);
  text-align:center;text-transform:uppercase;margin-bottom:3px;}
.ssid-l{text-align:center;font-size:10px;color:var(--muted);
  letter-spacing:1.5px;margin-bottom:16px;}
.ssid-l strong{color:var(--cyan2);}

/* Alert box */
.alert{background:rgba(255,170,0,.08);border:1px solid rgba(255,170,0,.3);
  border-radius:8px;padding:12px 14px;font-size:11px;color:var(--amber);
  text-align:center;margin-bottom:14px;line-height:1.6;}

.step{display:flex;gap:10px;align-items:flex-start;margin-bottom:9px;}
.sn{min-width:19px;height:19px;border-radius:50%;
  background:rgba(0,255,224,.1);border:1px solid rgba(0,255,224,.3);
  color:var(--cyan);font-size:9px;display:flex;align-items:center;
  justify-content:center;flex-shrink:0;margin-top:1px;}
.st{font-size:11px;color:var(--text);line-height:1.6;}
.st strong{color:var(--amber);}
.st em{color:var(--cyan2);font-style:normal;}

.div{display:flex;align-items:center;gap:8px;margin:14px 0 11px;}
.div::before,.div::after{content:'';flex:1;height:1px;background:var(--border);}
.div span{font-size:8px;color:var(--muted);letter-spacing:2px;
  text-transform:uppercase;white-space:nowrap;}

.req-btn{width:100%;padding:13px;background:rgba(0,255,224,.08);
  border:1px solid rgba(0,255,224,.3);border-radius:8px;
  color:var(--cyan);font-family:var(--mono);font-size:11px;
  letter-spacing:2px;text-transform:uppercase;cursor:pointer;
  transition:all .2s;margin-bottom:8px;}
.req-btn:hover:not(:disabled){background:rgba(0,255,224,.18);}
.req-btn:disabled{opacity:.4;cursor:not-allowed;}

.otp-row{display:flex;gap:7px;margin-bottom:0;}
.otp-in{flex:1;background:rgba(0,255,224,.04);
  border:1px solid var(--border);color:var(--cyan);
  font-family:var(--mono);font-size:22px;padding:11px 10px;
  border-radius:6px;outline:none;letter-spacing:8px;text-align:center;}
.otp-in:focus{border-color:rgba(0,255,224,.5);}
.otp-in::placeholder{letter-spacing:4px;font-size:12px;color:var(--muted);}
.otp-in:disabled{opacity:.4;}
.otp-btn{padding:11px 14px;background:rgba(0,255,224,.1);
  border:1px solid rgba(0,255,224,.3);border-radius:6px;
  color:var(--cyan);font-family:var(--mono);font-size:10px;
  letter-spacing:2px;text-transform:uppercase;cursor:pointer;
  transition:all .2s;white-space:nowrap;}
.otp-btn:hover:not(:disabled){background:rgba(0,255,224,.2);}
.otp-btn:disabled{opacity:.4;cursor:not-allowed;}

.msg{margin-top:9px;padding:9px 12px;border-radius:6px;
  font-size:11px;line-height:1.5;display:none;}
.msg.show{display:block;}
.msg.ok{background:rgba(0,255,136,.08);color:var(--green);
  border:1px solid rgba(0,255,136,.25);}
.msg.err{background:rgba(255,34,68,.08);color:#ff8899;
  border:1px solid rgba(255,34,68,.25);}
.msg.warn{background:rgba(255,170,0,.08);color:var(--amber);
  border:1px solid rgba(255,170,0,.2);}
.timer{font-size:10px;color:var(--muted);margin-top:6px;}
.timer span{color:var(--amber);}

.status-badge{padding:5px 10px;border-radius:4px;font-size:9px;
  letter-spacing:1.5px;text-transform:uppercase;text-align:center;
  margin-bottom:8px;display:none;}
.status-badge.show{display:block;}
.badge-wait{background:rgba(255,170,0,.08);color:var(--amber);
  border:1px solid rgba(255,170,0,.2);}
.badge-ready{background:rgba(0,255,136,.08);color:var(--green);
  border:1px solid rgba(0,255,136,.25);}

/* success */
.before-otp.hide{display:none;}
.success-state{display:none;}
.success-state.show{display:block;}
.success-box{background:rgba(0,255,136,.06);border:1px solid rgba(0,255,136,.25);
  border-radius:10px;padding:16px;text-align:center;margin-bottom:14px;}
.tick{font-size:32px;margin-bottom:7px;}
.success-box h2{font-size:13px;color:var(--green);letter-spacing:2px;
  text-transform:uppercase;margin-bottom:5px;}
.success-box p{font-size:11px;color:var(--muted);line-height:1.6;}
.dl{display:flex;align-items:center;gap:10px;width:100%;
  padding:12px 13px;border:1px solid var(--border);border-radius:8px;
  background:transparent;color:var(--text);font-family:var(--mono);
  text-decoration:none;transition:all .2s;margin-bottom:8px;}
.dl:hover{background:rgba(0,255,224,.06);border-color:rgba(0,255,224,.3);}
.dl-icon{width:32px;height:32px;border-radius:6px;display:flex;
  align-items:center;justify-content:center;font-size:16px;flex-shrink:0;}
.dl-ios{background:rgba(0,191,170,.15);}
.dl-and{background:rgba(0,255,136,.1);}
.dl-cert{background:rgba(167,139,250,.15);}
.dl-lbl strong{display:block;font-size:11px;color:var(--cyan2);}
.dl-lbl span{font-size:10px;color:var(--muted);}
.cert-box{background:rgba(167,139,250,.06);border:1px solid rgba(167,139,250,.25);
  border-radius:10px;padding:14px;margin-top:12px;}
.cert-box h3{font-size:10px;color:var(--purple);letter-spacing:2px;
  text-transform:uppercase;margin-bottom:6px;}
.cert-box p{font-size:11px;color:var(--muted);line-height:1.6;margin-bottom:10px;}
.cert-id-box{background:rgba(0,0,0,.3);border:1px solid rgba(167,139,250,.2);
  border-radius:5px;padding:8px;text-align:center;font-size:12px;
  color:var(--purple);letter-spacing:3px;margin-bottom:10px;font-family:monospace;}
.footer{text-align:center;font-size:9px;color:var(--muted);
  letter-spacing:1px;margin-top:14px;opacity:.6;}
</style>
</head>
<body>
<div class="card">
  <div class="shield">
    <svg viewBox="0 0 56 56" fill="none">
      <path d="M28 4L6 16v13c0 12.7 9.5 24.6 22 27 12.5-2.4 22-14.3 22-27V16L28 4z"
            stroke="#00ffe0" stroke-width="1.5" fill="rgba(0,255,224,.05)"/>
      <path d="M20 28l6 6 10-10" stroke="#00ffe0" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  </div>
  <h1>Network Access Required</h1>
  <p class="ssid-l">Network: <strong>{{ ssid }}</strong></p>

  <div class="alert">
    ⛔ Your device has no internet access.<br>
    All traffic (TCP, UDP, IPv6) is blocked.<br>
    Contact IT admin to get access.
  </div>

  <!-- BEFORE OTP -->
  <div id="beforeOTP">
    <div class="step">
      <div class="sn">1</div>
      <div class="st">Tap <strong>Request OTP</strong> below to notify your
        <em>IT administrator</em>.</div>
    </div>
    <div class="step">
      <div class="sn">2</div>
      <div class="st">Admin will verify your identity and give you a
        <strong>6-digit OTP</strong> verbally.</div>
    </div>
    <div class="step">
      <div class="sn">3</div>
      <div class="st">Enter OTP below to get full internet access.</div>
    </div>

    <div class="status-badge badge-wait" id="waitBadge">
      ⏳ Waiting for admin to send OTP...
    </div>
    <div class="status-badge badge-ready" id="readyBadge">
      ✓ OTP ready — enter it below
    </div>

    <div class="div"><span>Step 1</span></div>
    <button class="req-btn" id="reqBtn" onclick="requestOTP()">
      📲 Request OTP from Administrator
    </button>
    <div id="reqMsg" class="msg"></div>

    <div class="div"><span>Step 2 — Enter OTP</span></div>
    <div class="otp-row">
      <input class="otp-in" id="otpIn" type="text"
        inputmode="numeric" pattern="[0-9]*"
        maxlength="6" placeholder="• • • • • •"
        autocomplete="one-time-code" disabled>
      <button class="otp-btn" id="otpBtn" onclick="submitOTP()" disabled>
        SUBMIT
      </button>
    </div>
    <div id="otpMsg" class="msg"></div>
    <div class="timer" id="timer"></div>
  </div>

  <!-- AFTER OTP -->
  <div class="success-state" id="afterOTP">
    <div class="success-box">
      <div class="tick">✅</div>
      <h2>Access Granted!</h2>
      <p>All internet traffic restored.<br>
        <strong>TCP, UDP, IPv6 — all active.</strong></p>
    </div>
    <div class="div"><span>Download Wi-Fi Profile</span></div>
    <a class="dl" href="/api/wifi_profile/ios">
      <div class="dl-icon dl-ios">📱</div>
      <div class="dl-lbl">
        <strong>iPhone / iPad Profile</strong>
        <span>Tap to download .mobileconfig</span>
      </div>
    </a>
    <a class="dl" href="/api/wifi_profile/android">
      <div class="dl-icon dl-and">🤖</div>
      <div class="dl-lbl">
        <strong>Android Profile</strong>
        <span>Tap to download .xml</span>
      </div>
    </a>
    <div class="cert-box">
      <h3>📜 Device Certificate</h3>
      <p>Your official proof of network authorization for
        <strong>{{ ssid }}</strong>.</p>
      <div class="cert-id-box" id="certIdBox">Generating...</div>
      <a class="dl" id="certDl" href="#" style="text-decoration:none;">
        <div class="dl-icon dl-cert">📜</div>
        <div class="dl-lbl">
          <strong>Download Certificate</strong>
          <span>HTML file — save as audit record</span>
        </div>
      </a>
    </div>
  </div>

  <div class="footer">
    WIDS v3.0 · Secured Network · Contact IT admin for help
  </div>
</div>

<script>
const MAC="{{ mac }}";
let _requested=false;
let timerInt;

function showMsg(id,text,type){
  const m=document.getElementById(id);
  m.textContent=text;m.className='msg '+type+' show';}
function hideMsg(id){document.getElementById(id).className='msg';}

async function requestOTP(){
  const btn=document.getElementById('reqBtn');
  btn.disabled=true;btn.textContent='Sending request...';
  hideMsg('reqMsg');
  try{
    const res=await fetch('/captive/request_otp',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({mac:MAC})});
    const data=await res.json();
    if(data.status==='ok'){
      _requested=true;
      showMsg('reqMsg','✓ Request sent! Admin will send you the OTP shortly.','ok');
      btn.textContent='✓ Request Sent';
      document.getElementById('otpIn').disabled=false;
      document.getElementById('otpBtn').disabled=false;
      document.getElementById('otpIn').focus();
      document.getElementById('waitBadge').classList.add('show');
      timerInt=setInterval(pollStatus,4000);
    }else{
      showMsg('reqMsg',data.message||'Error. Try again.','warn');
      btn.disabled=false;
      btn.textContent='📲 Request OTP from Administrator';}
  }catch(e){
    showMsg('reqMsg','Network error. Try again.','err');
    btn.disabled=false;
    btn.textContent='📲 Request OTP from Administrator';}
}

async function submitOTP(){
  const otp=document.getElementById('otpIn').value.trim();
  if(otp.length!==6){showMsg('otpMsg','Enter all 6 digits.','warn');return;}
  const btn=document.getElementById('otpBtn');
  btn.disabled=true;btn.textContent='...';
  hideMsg('otpMsg');
  try{
    const res=await fetch('/captive/verify_otp',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({mac:MAC,otp:otp})});
    const data=await res.json();
    if(data.status==='ok'){
      clearInterval(timerInt);
      document.getElementById('beforeOTP').className='before-otp hide';
      document.getElementById('afterOTP').className='success-state show';
      if(data.cert_id)
        document.getElementById('certIdBox').textContent='CERT-'+data.cert_id;
      if(data.cert_url){
        const c=document.getElementById('certDl');
        c.href=data.cert_url;c.setAttribute('download','');}
    }else if(data.status==='wrong'){
      showMsg('otpMsg','✗ Wrong OTP. '+data.message,'err');
      document.getElementById('otpIn').value='';
      document.getElementById('otpIn').focus();
      btn.disabled=false;btn.textContent='SUBMIT';
    }else if(data.status==='locked'){
      showMsg('otpMsg','🔒 '+data.message,'err');
      btn.textContent='LOCKED';
      document.getElementById('otpIn').disabled=true;
    }else if(data.status==='expired'){
      showMsg('otpMsg','⏱ OTP expired. Request a new one.','warn');
      document.getElementById('otpIn').value='';
      document.getElementById('reqBtn').disabled=false;
      document.getElementById('reqBtn').textContent='📲 Request OTP from Administrator';
      document.getElementById('waitBadge').classList.remove('show');
      document.getElementById('readyBadge').classList.remove('show');
      btn.disabled=false;btn.textContent='SUBMIT';
    }else{
      showMsg('otpMsg',data.message||'Error.','warn');
      btn.disabled=false;btn.textContent='SUBMIT';}
  }catch(e){
    showMsg('otpMsg','Network error.','err');
    btn.disabled=false;btn.textContent='SUBMIT';}
}

async function pollStatus(){
  try{
    const res=await fetch('/captive/otp_status?mac='+encodeURIComponent(MAC));
    const d=await res.json();
    const t=document.getElementById('timer');
    const wb=document.getElementById('waitBadge');
    const rb=document.getElementById('readyBadge');
    if(d.status==='pending'){
      wb.classList.remove('show');rb.classList.add('show');
      const m=Math.floor(d.remaining/60),s=d.remaining%60;
      t.innerHTML='OTP expires: <span>'+m+':'+String(s).padStart(2,'0')+'</span>';
      document.getElementById('otpIn').disabled=false;
      document.getElementById('otpBtn').disabled=false;
    }else if(d.status==='expired'){
      t.innerHTML='<span>OTP expired</span> — request again.';
      rb.classList.remove('show');wb.classList.remove('show');
    }else if(d.status==='locked'){
      t.innerHTML='<span>Locked</span> — wait '+d.remaining+'s.';
    }else if(d.status==='requested'){
      wb.classList.add('show');
      t.innerHTML='Waiting for admin... ('+d.seconds_ago+'s ago)';
    }else{
      if(_requested) t.innerHTML='Waiting for admin to send OTP...';}}
  catch(e){}
}

document.getElementById('otpIn').addEventListener('input',function(){
  this.value=this.value.replace(/[^0-9]/g,'');
  if(this.value.length===6&&!this.disabled) submitOTP();
});
</script>
</body>
</html>"""

@captive_bp.route('/captive')
def captive_page():
    client_ip = request.remote_addr
    mac       = _ip_to_mac(client_ip) or "unknown"
    return render_template_string(PORTAL_HTML, ssid=YOUR_SSID, mac=mac)

@captive_bp.route('/captive/request_otp', methods=['POST'])
def captive_request_otp():
    from otp_manager import request_otp
    data      = request.json or {}
    mac       = data.get('mac','').upper().strip()
    client_ip = request.remote_addr
    if not mac or mac == 'UNKNOWN':
        mac = _ip_to_mac(client_ip) or ''
    if not mac:
        return jsonify({'status':'error','message':'Cannot identify device.'}), 400
    ip = _mac_to_ip(mac) or client_ip
    ok, msg = request_otp(mac, ip)
    if ok:
        return jsonify({'status':'ok', 'message':msg})
    return jsonify({'status':'cooldown', 'message':msg})

@captive_bp.route('/captive/verify_otp', methods=['POST'])
def verify_otp():
    from otp_manager  import validate_otp
    from cert_manager import generate_device_certificate
    data      = request.json or {}
    mac       = data.get('mac','').upper().strip()
    otp       = str(data.get('otp','')).strip()
    client_ip = request.remote_addr
    if not mac or mac == 'UNKNOWN':
        mac = _ip_to_mac(client_ip) or ''
    if not mac:
        return jsonify({'status':'error','message':'Cannot identify device.'}), 400
    result, detail = validate_otp(mac, otp)
    if result == 'ok':
        target_ip = detail
        if not target_ip or target_ip == 'N/A':
            target_ip = _mac_to_ip(mac) or client_ip
        remove_strict_captive_rules(target_ip)
        mark_mac_approved(mac)
        _authorize_in_server(mac)
        real_ip = target_ip if target_ip else client_ip
        try:
            cert_path, cert_id = generate_device_certificate(
                mac=mac, ip=real_ip,
                device_name=f"Device {mac[-8:]}",
                issued_by="WIDS System (OTP Verified)",
                network_name=YOUR_SSID)
            _save_cert_db(mac, real_ip, cert_id)
        except Exception as e:
            print(f"[CAPTIVE] Cert error: {e}")
            cert_id = "ERROR"
        print(f"[CAPTIVE] ✅ OTP OK — {mac} @ {real_ip}")
        return jsonify({'status':'ok','cert_id':cert_id,
                        'cert_url':f"/api/cert/{mac}"})
    return jsonify({'status':result,'message':detail})

@captive_bp.route('/captive/otp_status')
def otp_status_route():
    from otp_manager import get_otp_status
    mac = request.args.get('mac','').upper().strip()
    if not mac:
        mac = _ip_to_mac(request.remote_addr) or ''
    return jsonify(get_otp_status(mac))

@captive_bp.route('/api/wifi_profile/ios')
def wifi_ios():
    client_ip = request.remote_addr
    mac = _ip_to_mac(client_ip)
    if not mac or not is_mac_approved(mac):
        return ('<html><body style="background:#030810;color:#ff8899;'
                'font-family:monospace;text-align:center;padding:40px">'
                '<h2>🔒 OTP required first</h2>'
                '<p><a href="/captive" style="color:#00ffe0">← Back</a></p>'
                '</body></html>'), 403
    from cert_manager import generate_wifi_profile_ios, get_wifi_profile_path
    path = get_wifi_profile_path(YOUR_SSID, 'ios')
    if not os.path.exists(path):
        path = generate_wifi_profile_ios(YOUR_SSID, WIFI_PASSWORD or None)
    return send_file(path, mimetype='application/x-apple-aspen-config',
                     as_attachment=True,
                     download_name=f"wifi_{YOUR_SSID}.mobileconfig")

@captive_bp.route('/api/wifi_profile/android')
def wifi_android():
    client_ip = request.remote_addr
    mac = _ip_to_mac(client_ip)
    if not mac or not is_mac_approved(mac):
        return ('<html><body style="background:#030810;color:#ff8899;'
                'font-family:monospace;text-align:center;padding:40px">'
                '<h2>🔒 OTP required first</h2>'
                '<p><a href="/captive" style="color:#00ffe0">← Back</a></p>'
                '</body></html>'), 403
    from cert_manager import generate_wifi_profile_android, get_wifi_profile_path
    path = get_wifi_profile_path(YOUR_SSID, 'android')
    if not os.path.exists(path):
        path = generate_wifi_profile_android(YOUR_SSID, WIFI_PASSWORD or None)
    return send_file(path, mimetype='text/xml',
                     as_attachment=True,
                     download_name=f"wifi_{YOUR_SSID}.xml")

def _authorize_in_server(mac):
    import requests as req, os as _os
    try:
        token = _os.environ.get("WIDS_TOKEN","wids-change-this-token")
        req.post(f"http://127.0.0.1:8000/api/authorize/{mac}",
                 headers={"X-WIDS-Token":token}, timeout=3)
    except Exception as e:
        print(f"[CAPTIVE] Auto-authorize error: {e}")

def _save_cert_db(mac, ip, cert_id):
    import sqlite3, os as _os
    db = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),"wids_database.db")
    try:
        conn = sqlite3.connect(db)
        conn.execute("INSERT OR REPLACE INTO device_certs "
                     "(mac,ip,device_name,cert_id) VALUES(?,?,?,?)",
                     (mac,ip,f"Device {mac[-8:]}",cert_id))
        conn.commit(); conn.close()
    except Exception as e:
        print(f"[CAPTIVE] DB error: {e}")
