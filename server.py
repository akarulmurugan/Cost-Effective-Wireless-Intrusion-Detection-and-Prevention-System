#!/usr/bin/env python3
"""
WIDS v3.0 — server.py

FIXES:
  1. IPv6 COMPLETELY BLOCKED — ip6tables blocks ALL IPv6 traffic
     (not just forwarding — also INPUT/OUTPUT for the device)
  2. UDP COMPLETELY BLOCKED — iptables blocks ALL UDP in FORWARD
     (covers QUIC/HTTP3 on port 443, games, DNS, NTP)
  3. Own machine internet NEVER blocked — OUTPUT ACCEPT at highest
     priority, re-applied after every arpspoof start
  4. Deauth fires continuously every 5s even if PMF blocks it
     (keeps pressure, works on non-PMF devices)
  5. Mobile popup — SERVER_IP set correctly, all OS detection URLs
     handled, Cache-Control headers prevent caching
"""
import os,json,time,sqlite3,threading,subprocess,re,struct
import signal,atexit,sys,logging,secrets
from flask import (Flask,request,jsonify,send_file,redirect,make_response)
try:
    from scapy.all import (RadioTap,Dot11,Dot11Deauth,sendp,ARP,
                            IPv6,ICMPv6ND_NA,ICMPv6NDOptDstLLAddr,Ether)
    SCAPY=True
except: SCAPY=False
try: import serial
except: serial=None

from admin_auth    import (verify_credentials,verify_login_otp,
                            validate_session,destroy_session,
                            get_active_session,get_auth_log)
from otp_manager   import (send_otp_to_device,revoke_otp,
                            get_otp_status,get_pending_requests,has_pending_otp)
from captive_portal import (captive_bp,apply_strict_captive_rules,
                              remove_strict_captive_rules)
from cert_manager  import (generate_wifi_profile_ios,generate_wifi_profile_android,
                            generate_device_certificate,get_cert_path,
                            get_wifi_profile_path)
from telegram_alerts import (alert_intruder,alert_flood,
                              alert_authorized,alert_cert_issued,alert_startup)

app=Flask(__name__)
app.secret_key=secrets.token_hex(32)
logging.getLogger('werkzeug').setLevel(logging.ERROR)
app.register_blueprint(captive_bp)
SERVER_START_TIME=time.time()

# ── CONFIG ────────────────────────────────────────────────────────
YOUR_SSID     = "Airtel_Zerotouch-2"
ROUTER_BSSIDS = [
    "A0:91:CA:3C:35:9A",
    "A6:91:CA:3C:35:9A",
    "A0:91:CA:3C:35:91",
    "9E:5A:91:B4:DB:CD",
    "1A:5D:DC:16:23:59"
]
L3_INTERFACE  = "eth0"
L2_INTERFACE  = "wlan0"
ESP32_PORT    = '/dev/ttyUSB0'
ESP32_BAUD    = 115200
API_TOKEN     = os.environ.get("WIDS_TOKEN","wids-change-this-token")
WIFI_PASSWORD = os.environ.get("WIFI_PASS","")
ENABLE_HTTPS  = False

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_FILE   = os.path.join(BASE_DIR,"wids_database.db")
AUTH_FILE = os.path.join(BASE_DIR,"authorized_macs.json")
CERT_DIR  = os.path.join(BASE_DIR,"certs")
LOGIN_FILE= os.path.join(BASE_DIR,"login.html")
DASH_FILE = os.path.join(BASE_DIR,"dashboard.html")
os.makedirs(CERT_DIR,exist_ok=True)

import captive_portal as _cp
_cp.YOUR_SSID=YOUR_SSID; _cp.WIFI_PASSWORD=WIFI_PASSWORD
_cp.L3_INTERFACE=L3_INTERFACE; _cp.CERT_DIR=CERT_DIR

# ── STATE ─────────────────────────────────────────────────────────
_lock=threading.Lock()
_file_lock=threading.Lock()
authorized_macs=set()
active_mitigations={}
packets_buffer=[]
packet_count_history=[]
recent_unauthorized=[]
esp32_active=False
OWN_MACS=set()
MAC_FLOOD_THRESHOLD=4
FLOOD_TIME_WINDOW=15
print("[SYSTEM] WIDS v3.0 booting...")

# ══════════════════════════════════════════════════════════════════
# INIT — flush rules and protect own machine
# ══════════════════════════════════════════════════════════════════
def init_system():
    global authorized_macs,OWN_MACS
    print("[SYSTEM] Flushing iptables rules...")
    for cmd in [
        ["sudo","iptables","-F"],
        ["sudo","iptables","-F","-t","nat"],
        ["sudo","iptables","-F","-t","mangle"],
        ["sudo","ip6tables","-F"],
        ["sudo","ip6tables","-F","-t","nat"],
        ["sudo","iptables","-P","FORWARD","ACCEPT"],
        ["sudo","iptables","-P","INPUT","ACCEPT"],
        ["sudo","iptables","-P","OUTPUT","ACCEPT"],
        ["sudo","ip6tables","-P","FORWARD","ACCEPT"],
        ["sudo","ip6tables","-P","INPUT","ACCEPT"],
        ["sudo","ip6tables","-P","OUTPUT","ACCEPT"],
    ]:
        subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    subprocess.run(["sudo","sysctl","-w","net.ipv4.ip_forward=1"],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(["sudo","sysctl","-w","net.ipv6.conf.all.forwarding=1"],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    # ── CRITICAL: Protect own machine FIRST ──────────────────────
    # These rules ensure our machine always has internet
    # regardless of what arpspoof does to other devices.
    _protect_own_machine()
    print("[SYSTEM] IP forwarding enabled, own machine protected")

    # ── DB ────────────────────────────────────────────────────────
    conn=sqlite3.connect(DB_FILE)
    for sql in [
        '''CREATE TABLE IF NOT EXISTS blocked_devices(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,ip TEXT,reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,status TEXT)''',
        '''CREATE TABLE IF NOT EXISTS device_certs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT UNIQUE,ip TEXT,device_name TEXT,
            cert_id TEXT,issued_on DATETIME DEFAULT CURRENT_TIMESTAMP)''',
        '''CREATE TABLE IF NOT EXISTS auth_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT,ip TEXT,detail TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''',
    ]:
        conn.execute(sql)
    conn.commit(); conn.close()

    with _file_lock:
        if os.path.exists(AUTH_FILE):
            try:
                with open(AUTH_FILE) as f:
                    authorized_macs=set(json.load(f))
            except: authorized_macs=set()

    OWN_MACS=_get_own_macs()
    print(f"[SYSTEM] Own MACs (protected): {OWN_MACS}")
    with _lock:
        authorized_macs.update(OWN_MACS)
        for b in ROUTER_BSSIDS:
            authorized_macs.add(b.upper())
    save_auth()

def _protect_own_machine():
    """
    Apply iptables rules that ensure OUR machine ALWAYS has internet.
    These are inserted at the TOP of the chain (highest priority).
    Must be called:
      1. At startup
      2. After every arpspoof start (arpspoof can disrupt routing)
      3. After every l3_grant
    """
    for cmd in [
        # Our outgoing traffic ALWAYS accepted — Telegram API, DNS, updates
        ["sudo","iptables","-I","OUTPUT","-j","ACCEPT"],
        # Our incoming replies ALWAYS accepted (ESTABLISHED/RELATED)
        ["sudo","iptables","-I","INPUT","-m","state",
         "--state","ESTABLISHED,RELATED","-j","ACCEPT"],
        # Forwarded established connections allowed
        ["sudo","iptables","-I","FORWARD","-m","state",
         "--state","ESTABLISHED,RELATED","-j","ACCEPT"],
        # Explicit DNS out (belt and suspenders)
        ["sudo","iptables","-I","OUTPUT","-p","udp","--dport","53","-j","ACCEPT"],
        ["sudo","iptables","-I","OUTPUT","-p","tcp","--dport","53","-j","ACCEPT"],
        # HTTPS out for Telegram API
        ["sudo","iptables","-I","OUTPUT","-p","tcp","--dport","443","-j","ACCEPT"],
        # HTTP out
        ["sudo","iptables","-I","OUTPUT","-p","tcp","--dport","80","-j","ACCEPT"],
        # IPv6 — our machine can use IPv6 freely
        ["sudo","ip6tables","-I","OUTPUT","-j","ACCEPT"],
        ["sudo","ip6tables","-I","INPUT","-m","state",
         "--state","ESTABLISHED,RELATED","-j","ACCEPT"],
    ]:
        subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def _get_own_macs():
    macs=set()
    for iface in [L3_INTERFACE,L2_INTERFACE,"eth0","eth1","wlan0","wlan1"]:
        try:
            with open(f"/sys/class/net/{iface}/address") as f:
                m=f.read().strip().upper()
                if m and m!="00:00:00:00:00:00": macs.add(m)
        except: pass
    return macs

def _get_own_ip():
    try:
        out=subprocess.check_output(["ip","addr","show",L3_INTERFACE],
                                    stderr=subprocess.DEVNULL).decode()
        for l in out.splitlines():
            if "inet " in l:
                return l.strip().split()[1].split('/')[0]
    except: pass
    return None

def save_auth():
    tmp=AUTH_FILE+".tmp"
    with _file_lock:
        with open(tmp,'w') as f: json.dump(list(authorized_macs),f,indent=4)
        os.replace(tmp,AUTH_FILE)

# ── NETWORK UTILS ─────────────────────────────────────────────────
def gw4():
    try:
        out=subprocess.check_output(["ip","route","show","default"],
                                    stderr=subprocess.DEVNULL).decode()
        for l in out.splitlines():
            p=l.split()
            if "default" in p and "via" in p: return p[p.index("via")+1]
    except: pass
    return "192.168.1.1"

def gw6():
    try:
        out=subprocess.check_output(["ip","-6","route","show","default"],
                                    stderr=subprocess.DEVNULL).decode()
        for l in out.splitlines():
            p=l.split()
            if "default" in p and "via" in p: return p[p.index("via")+1]
    except: pass
    return None

def our_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().upper()
    except: return None

def ipv6_for_mac(mac):
    try:
        out=subprocess.check_output(["ip","-6","neigh","show"],
                                    stderr=subprocess.DEVNULL).decode()
        return [l.split()[0] for l in out.splitlines()
                if len(l.split())>=5 and l.split()[4].upper()==mac.upper()]
    except: return []

def ip_for_mac(mac):
    try:
        out=subprocess.check_output(["arp","-n"],
                                    stderr=subprocess.DEVNULL).decode()
        for l in out.splitlines():
            if mac.lower() in l.lower():
                p=l.split()
                if p: return p[0]
    except: pass
    return None

def detect_flood(mac):
    now=time.time()
    with _lock:
        recent_unauthorized.append((mac,now))
        cutoff=now-FLOOD_TIME_WINDOW
        while recent_unauthorized and recent_unauthorized[0][1]<cutoff:
            recent_unauthorized.pop(0)
        unique={m for m,_ in recent_unauthorized}
        if len(unique)>=MAC_FLOOD_THRESHOLD:
            alert_flood(len(unique),FLOOD_TIME_WINDOW)
            return True
    return False

# ══════════════════════════════════════════════════════════════════
# L2 — CONTINUOUS DEAUTH
# Even if PMF blocks deauth frames, we keep sending them.
# Reason: PMF protects management frames but some older devices
# and chipsets still respond. Continuous deauth also prevents
# the device from stabilising its connection.
# ══════════════════════════════════════════════════════════════════
def l2_deauth_continuous(mac, stop_event):
    """
    Keep sending deauth frames every 5 seconds until stop_event is set.
    Works against non-PMF devices.
    PMF devices ignore it but it costs us nothing to keep trying.
    """
    if not SCAPY:
        return
    print(f"[L2] Continuous deauth started → {mac}")
    while not stop_event.is_set():
        try:
            for bssid in ROUTER_BSSIDS:
                # Deauth to device (from AP)
                pkt1=(RadioTap()/
                      Dot11(addr1=mac,addr2=bssid,addr3=bssid)/
                      Dot11Deauth(reason=7))
                # Deauth to AP (from device) — double deauth
                pkt2=(RadioTap()/
                      Dot11(addr1=bssid,addr2=mac,addr3=bssid)/
                      Dot11Deauth(reason=7))
                sendp(pkt1,iface=L2_INTERFACE,count=3,inter=0.05,verbose=0)
                sendp(pkt2,iface=L2_INTERFACE,count=3,inter=0.05,verbose=0)
        except Exception as e:
            print(f"[L2] {e}")
        stop_event.wait(5)   # send every 5 seconds
    print(f"[L2] Continuous deauth stopped → {mac}")

# ══════════════════════════════════════════════════════════════════
# L3 — FULL IPv4 + IPv6 ISOLATION
# ══════════════════════════════════════════════════════════════════
def _ndp_loop(tip6,gip6,omac,stop):
    """Continuously poison NDP cache — blocks IPv6 internet."""
    if not SCAPY: return
    try:
        # Tell device: "I am the gateway" (poisoning device's cache)
        pt=(Ether(dst="ff:ff:ff:ff:ff:ff")/
            IPv6(src=gip6,dst=tip6)/
            ICMPv6ND_NA(tgt=gip6,S=1,R=1,O=1)/
            ICMPv6NDOptDstLLAddr(lladdr=omac))
        # Tell gateway: "I am the device" (poisoning gateway's cache)
        pg=(Ether(dst="ff:ff:ff:ff:ff:ff")/
            IPv6(src=tip6,dst=gip6)/
            ICMPv6ND_NA(tgt=tip6,S=1,R=1,O=1)/
            ICMPv6NDOptDstLLAddr(lladdr=omac))
        while not stop.is_set():
            sendp(pt,iface=L3_INTERFACE,verbose=0)
            sendp(pg,iface=L3_INTERFACE,verbose=0)
            stop.wait(2)
    except Exception as e: print(f"[NDP] {e}")

def _apply_ipv6_block(mac, addrs):
    """
    Block ALL IPv6 traffic from this device.
    ip6tables FORWARD drop — covers all IPv6 apps including YouTube QUIC.
    """
    # Block by MAC (catches link-local addresses we might miss)
    subprocess.run(["sudo","ip6tables","-I","FORWARD",
                    "-m","mac","--mac-source",mac,"-j","DROP"],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    # Block by each known IPv6 address
    for a in addrs:
        subprocess.run(["sudo","ip6tables","-I","FORWARD","-s",a,"-j","DROP"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["sudo","ip6tables","-I","FORWARD","-d",a,"-j","DROP"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["sudo","ip6tables","-I","INPUT","-s",a,"-j","DROP"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    print(f"[IPv6] Blocked {mac} — {len(addrs)} IPv6 addresses + MAC rule")

def _remove_ipv6_block(mac, addrs):
    subprocess.run(["sudo","ip6tables","-D","FORWARD",
                    "-m","mac","--mac-source",mac,"-j","DROP"],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for a in addrs:
        subprocess.run(["sudo","ip6tables","-D","FORWARD","-s",a,"-j","DROP"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["sudo","ip6tables","-D","FORWARD","-d",a,"-j","DROP"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["sudo","ip6tables","-D","INPUT","-s",a,"-j","DROP"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def l3_isolate(mac,ip):
    own_ip=_get_own_ip()
    if ip==own_ip or mac in OWN_MACS:
        print(f"[SAFE] Skip own machine {mac}/{ip}")
        return None,None,None,threading.Event(),[]

    g4=gw4(); g6=gw6(); om=our_mac(L3_INTERFACE); a6=ipv6_for_mac(mac)
    print(f"[L3] Isolating {mac} @ {ip} | GW4={g4} | IPv6 addrs={a6}")

    # ARP poison for IPv4
    p1=subprocess.Popen(["sudo","arpspoof","-i",L3_INTERFACE,"-t",ip,g4],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    p2=subprocess.Popen(["sudo","arpspoof","-i",L3_INTERFACE,"-t",g4,ip],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    # Re-protect own machine immediately after arpspoof starts
    _protect_own_machine()

    # Apply iptables captive rules (blocks ALL TCP, UDP, ICMP)
    apply_strict_captive_rules(ip)

    # Block ALL IPv6 by MAC rule + address rules
    _apply_ipv6_block(mac, a6)

    # Start NDP poisoning for IPv6
    ndp_stop=threading.Event()
    if om and g6:
        if a6:
            for addr in a6:
                threading.Thread(target=_ndp_loop,
                                 args=(addr,g6,om,ndp_stop),
                                 daemon=True).start()
        else:
            # Even without known IPv6 addrs, block by MAC rule (already applied above)
            print(f"[IPv6] No IPv6 addrs found for {mac} — MAC rule applied")

    # Continuous deauth (L2)
    deauth_stop=threading.Event()
    threading.Thread(target=l2_deauth_continuous,
                     args=(mac,deauth_stop),daemon=True).start()

    return p1,p2,deauth_stop,ndp_stop,a6

def l3_grant(mac,ip,data):
    """Remove ALL restrictions — called after OTP validated."""
    # Remove iptables captive rules
    remove_strict_captive_rules(ip)

    # Stop NDP poisoning
    ndp=data.get('ndp_stop')
    if ndp: ndp.set()

    # Stop continuous deauth
    deauth=data.get('deauth_stop')
    if deauth: deauth.set()

    # Stop arpspoof
    for p in data.get('procs',()):
        if p:
            try: p.send_signal(signal.SIGINT); p.wait(timeout=3)
            except: pass

    # Remove IPv6 blocks
    _remove_ipv6_block(mac, data.get('ipv6_addrs',[]))

    # Re-protect own machine after removing spoof
    _protect_own_machine()
    print(f"[L3] ✅ Full internet restored — {mac} @ {ip}")

def execute_captive_defense(mac,ip,is_flood=False):
    mk=mac.upper()
    if mk in OWN_MACS: return False
    own_ip=_get_own_ip()
    if ip==own_ip: return False
    router=[b.upper() for b in ROUTER_BSSIDS]
    if mk in router: return False
    with _lock:
        if mk in authorized_macs: return False
        if mk in active_mitigations and not is_flood: return True

    print(f"\n[CAPTIVE DEFENSE] {mk} @ {ip}")
    p1,p2,deauth_stop,ndp_stop,a6=l3_isolate(mk,ip)

    with _lock:
        active_mitigations[mk]={
            'ip':ip,'status':'captive',
            'procs':(p1,p2),
            'deauth_stop':deauth_stop,
            'ndp_stop':ndp_stop,
            'ipv6_addrs':a6}

    # Alert admin — NO auto OTP (device must request manually)
    alert_intruder(mk,ip,"Unauthorized device — full blackhole active (TCP+UDP+IPv6)")

    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT id FROM blocked_devices "
              "WHERE mac=? AND status='captive'",(mk,))
    if not c.fetchone():
        c.execute("INSERT INTO blocked_devices "
                  "(mac,ip,reason,status) VALUES(?,?,?,?)",
                  (mk,ip,"Full blackhole — awaiting manual OTP","captive"))
        conn.commit()
    conn.close()
    return True

def stop_captive_and_authorize(mac):
    mc=mac.strip().upper()
    with _lock: data=active_mitigations.pop(mc,None)
    if data: l3_grant(mc,data['ip'],data)
    with _lock: authorized_macs.add(mc)
    save_auth()
    conn=sqlite3.connect(DB_FILE)
    conn.execute("UPDATE blocked_devices SET status='authorized' WHERE mac=?",(mc,))
    conn.commit(); conn.close()
    revoke_otp(mc)
    alert_authorized(mc)

def stop_mitigation(mac):
    mc=mac.strip().upper()
    with _lock: data=active_mitigations.pop(mc,None)
    if data: l3_grant(mc,data.get('ip',''),data)
    conn=sqlite3.connect(DB_FILE)
    conn.execute("UPDATE blocked_devices SET status='mitigated' WHERE mac=?",(mc,))
    conn.commit(); conn.close()
    revoke_otp(mc)

_cp._grant_internet=lambda mac,ip: stop_captive_and_authorize(mac)

# ── PASSIVE ARP ───────────────────────────────────────────────────
_arp_seen={}; _ARP_TTL=10

def _arp_handle(pkt):
    if not SCAPY or not pkt.haslayer(ARP): return
    mac=pkt[ARP].hwsrc.upper().strip()
    ip=pkt[ARP].psrc.strip()
    if (not mac or not ip or mac=="FF:FF:FF:FF:FF:FF"
            or mac=="00:00:00:00:00:00" or ip=="0.0.0.0"): return
    if mac in OWN_MACS: return
    own_ip=_get_own_ip()
    if ip==own_ip: return
    router=[b.upper() for b in ROUTER_BSSIDS]
    if mac in router: return
    now=time.time()
    if now-_arp_seen.get(mac,0)<_ARP_TTL: return
    _arp_seen[mac]=now
    with _lock:
        if mac in authorized_macs: return
        if mac in active_mitigations: return
    execute_captive_defense(mac,ip,detect_flood(mac))

def passive_arp_monitor():
    if not SCAPY: print("[PASSIVE-ARP] Scapy not available"); return
    try:
        from scapy.all import sniff
        print(f"[PASSIVE-ARP] Active on {L3_INTERFACE}")
        sniff(iface=L3_INTERFACE,filter="arp",prn=_arp_handle,store=0)
    except Exception as e: print(f"[PASSIVE-ARP] {e}")

def active_network_scanner():
    time.sleep(2); print(f"[SCANNER] Fallback scan on {L3_INTERFACE}")
    router=[b.upper() for b in ROUTER_BSSIDS]
    while True:
        try:
            own_ip=_get_own_ip()
            raw=subprocess.check_output(
                ["sudo","arp-scan","-I",L3_INTERFACE,"-l"],
                stderr=subprocess.DEVNULL).decode()
            for line in raw.splitlines():
                parts=line.split('\t')
                if len(parts)<2 or ':' not in parts[1]: continue
                ip=parts[0].strip(); mac=parts[1].strip().upper()
                if mac in OWN_MACS or ip==own_ip: continue
                if "incomplete" in mac.lower() or mac in router: continue
                with _lock:
                    if mac in authorized_macs or mac in active_mitigations: continue
                execute_captive_defense(mac,ip,detect_flood(mac))
        except: pass
        time.sleep(8)

def esp32_listener():
    global esp32_active; MAGIC=b'\xAA\xBB'
    while True:
        try:
            if serial is None: raise ImportError
            ser=serial.Serial(ESP32_PORT,ESP32_BAUD,timeout=1)
            print(f"[ESP32] Online ({ESP32_PORT})"); esp32_active=True
            buf=b''
            while True:
                buf+=ser.read(max(1,ser.in_waiting or 1))
                idx=buf.find(MAGIC)
                if idx==-1: buf=buf[-2:]; continue
                buf=buf[idx:]
                if len(buf)<44: continue
                frame=buf[:44]; buf=buf[44:]
                try: up=struct.unpack('<H 6B b B B 33s',frame)
                except: continue
                ms="%02X:%02X:%02X:%02X:%02X:%02X"%up[1:7]
                with _lock:
                    packet_count_history.append(time.time())
                    if up[9] in [2,3]: packets_buffer.append({'mac':ms})
                    if len(packets_buffer)>500: packets_buffer.pop(0)
        except: esp32_active=False; time.sleep(2)

# ── AUTH MIDDLEWARE ───────────────────────────────────────────────
PUBLIC_PATHS=[
    '/auth/login','/auth/verify_otp','/login',
    '/captive','/captive/verify_otp','/captive/otp_status',
    '/captive/request_otp',
    '/hotspot-detect.html','/generate_204','/gen_204',
    '/generate204','/connecttest.txt','/ncsi.txt',
    '/redirect','/canonical.html','/library/test/success.html',
    '/success.txt','/mobile/status.php','/bag',
    '/check_network_status.txt',
    '/api/wifi_profile/',
]

def _is_public(path):
    for p in PUBLIC_PATHS:
        if path.startswith(p): return True
    return False

@app.before_request
def auth_middleware():
    path=request.path
    if _is_public(path): return
    token=request.cookies.get('wids_session')
    result,msg=validate_session(token,request.remote_addr)
    if result!='ok':
        if path.startswith('/api'):
            return jsonify({'error':'unauthorized','reason':msg}),401
        return redirect('/login')

# ── AUTH ROUTES ───────────────────────────────────────────────────
@app.route('/login')
def login_page():
    token=request.cookies.get('wids_session')
    result,_=validate_session(token,request.remote_addr)
    if result=='ok': return redirect('/')
    return open(LOGIN_FILE).read()

@app.route('/auth/login',methods=['POST'])
def auth_login():
    data=request.json or {}
    status,message,ptok=verify_credentials(
        data.get('username','').strip(),
        data.get('password',''),
        request.remote_addr)
    if status=='ok':
        return jsonify({'status':'ok','message':message,'pending_token':ptok})
    return jsonify({'status':status,'message':message})

@app.route('/auth/verify_otp',methods=['POST'])
def auth_verify_otp():
    data=request.json or {}
    result,detail=verify_login_otp(
        data.get('pending_token',''),
        str(data.get('otp','')).strip(),
        request.remote_addr)
    if result=='ok':
        resp=make_response(jsonify({'status':'ok'}))
        resp.set_cookie('wids_session',detail,
                        httponly=True,samesite='Strict',
                        max_age=3600,secure=ENABLE_HTTPS)
        return resp
    return jsonify({'status':result,'message':detail})

@app.route('/auth/logout',methods=['POST'])
def auth_logout():
    token=request.cookies.get('wids_session')
    destroy_session(token)
    resp=make_response(jsonify({'status':'ok'}))
    resp.delete_cookie('wids_session')
    return resp

# ── DASHBOARD + API ───────────────────────────────────────────────
@app.route('/')
def dashboard():
    return open(DASH_FILE).read().replace(
        '{{ your_ssid }}',YOUR_SSID).replace(
        '{{ api_token }}',API_TOKEN)

@app.route('/api/stats')
def get_stats():
    now=time.time()
    with _lock:
        packet_count_history[:]=[t for t in packet_count_history if now-t<=60]
        ppm=len(packet_count_history); act=len(active_mitigations)
        hw=esp32_active
        router_set=set(b.upper() for b in ROUTER_BSSIDS)
        display=authorized_macs-OWN_MACS-router_set; ac=len(display)
    conn=sqlite3.connect(DB_FILE)
    bl=conn.execute("SELECT COUNT(DISTINCT mac) FROM blocked_devices "
                    "WHERE status IN ('captive','blocked')").fetchone()[0]
    conn.close()
    pending=len(get_pending_requests())
    return jsonify({
        'blocked_devices':bl,'authorized_count':ac,
        'hardware_active':hw,'l3_active_count':act,
        'packets_per_min':ppm,
        'uptime_seconds':int(now-SERVER_START_TIME),
        'pending_otp_requests':pending,
    })

@app.route('/api/authorized')
def get_auth_list():
    with _lock:
        router_set=set(b.upper() for b in ROUTER_BSSIDS)
        display=sorted(authorized_macs-OWN_MACS-router_set)
    return jsonify([{'mac':m} for m in display])

@app.route('/api/authorize/<mac>',methods=['POST'])
def auth_mac(mac):
    mc=mac.strip().upper()
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$',mc):
        return jsonify({'status':'invalid'}),400
    stop_captive_and_authorize(mc)
    return jsonify({'status':'authorized'})

@app.route('/api/unauthorize/<mac>',methods=['POST'])
def unauth_mac(mac):
    mc=mac.strip().upper()
    with _lock: authorized_macs.discard(mc)
    save_auth()
    return jsonify({'status':'unauthorized'})

@app.route('/api/blocked')
def get_blocked():
    conn=sqlite3.connect(DB_FILE)
    rows=conn.execute(
        "SELECT mac,ip,reason,timestamp,status FROM blocked_devices "
        "WHERE status IN ('captive','blocked') ORDER BY id DESC").fetchall()
    conn.close()
    pending_reqs={r['mac']:r for r in get_pending_requests()}
    result=[]
    for r in rows:
        result.append({'mac':r[0],'ip':r[1] or 'unknown',
                       'reason':r[2],'time':r[3],'status':r[4],
                       'otp_requested':r[0] in pending_reqs,
                       'has_otp':has_pending_otp(r[0])})
    return jsonify(result)

@app.route('/api/send_otp/<mac>',methods=['POST'])
def send_otp(mac):
    mc=mac.strip().upper()
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$',mc):
        return jsonify({'status':'invalid'}),400
    ip=ip_for_mac(mc) or 'unknown'
    otp=send_otp_to_device(mc,ip)
    return jsonify({'status':'sent','message':f'OTP sent for {mc}'})

@app.route('/api/pending_requests')
def pending_requests():
    return jsonify(get_pending_requests())

@app.route('/api/manual_block/<mac>',methods=['POST'])
def man_block(mac):
    mc=mac.strip().upper()
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$',mc):
        return jsonify({'status':'invalid'}),400
    if mc in OWN_MACS:
        return jsonify({'status':'error','detail':'Cannot block own machine'}),400
    tip=ip_for_mac(mc)
    if not tip: return jsonify({'status':'no_ip'}),202
    with _lock: authorized_macs.discard(mc)
    save_auth(); execute_captive_defense(mc,tip,False)
    return jsonify({'status':'blocked','ip':tip})

@app.route('/api/stop_mitigation/<mac>',methods=['POST'])
def stop_mit(mac): stop_mitigation(mac); return jsonify({'status':'stopped'})

@app.route('/api/issue_cert/<mac>',methods=['POST'])
def issue_cert(mac):
    mc=mac.strip().upper()
    with _lock:
        if mc not in authorized_macs:
            return jsonify({'status':'error','detail':'Not authorized'}),400
    data=request.json or {}
    name=data.get('device_name','Unknown Device')
    ip=ip_for_mac(mc) or data.get('ip','') or 'Unknown'
    path,cid=generate_device_certificate(mc,ip,name,
                issued_by=data.get('issued_by','WIDS Admin'),
                network_name=YOUR_SSID)
    conn=sqlite3.connect(DB_FILE)
    conn.execute("INSERT OR REPLACE INTO device_certs "
                 "(mac,ip,device_name,cert_id) VALUES(?,?,?,?)",
                 (mc,ip,name,cid))
    conn.commit(); conn.close()
    alert_cert_issued(mc,ip,cid)
    return jsonify({'status':'issued','cert_id':cid})

@app.route('/api/cert/<mac>')
def dl_cert(mac):
    mc=mac.strip().upper(); path=get_cert_path(mc)
    if not path: return jsonify({'status':'not_found'}),404
    return send_file(path,mimetype='text/html',as_attachment=True,
                     download_name=f"cert_{mc.replace(':','')}.html")

@app.route('/api/cert_list')
def cert_list():
    conn=sqlite3.connect(DB_FILE)
    rows=conn.execute("SELECT mac,ip,device_name,cert_id,issued_on "
                      "FROM device_certs ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([{'mac':r[0],'ip':r[1],'name':r[2],
                     'cert_id':r[3],'issued_on':r[4]} for r in rows])

@app.route('/api/auth_log')
def auth_log_route(): return jsonify(get_auth_log(30))

@app.route('/api/otp_status/<mac>')
def otp_st(mac): return jsonify(get_otp_status(mac.strip().upper()))

@app.route('/api/packet',methods=['POST'])
def recv_pkt():
    if request.json:
        with _lock:
            packets_buffer.append(request.json)
            packet_count_history.append(time.time())
    return jsonify({'status':'received'})

# ── SHUTDOWN ──────────────────────────────────────────────────────
def cleanup():
    print("\n[!] Shutdown — restoring network...")
    with _lock: items=list(active_mitigations.items())
    for mc,data in items:
        ip=data.get('ip','')
        if ip:
            try: l3_grant(mc,ip,data)
            except: pass
    for cmd in [
        ["sudo","iptables","-F"],
        ["sudo","iptables","-t","nat","-F"],
        ["sudo","ip6tables","-F"],
        ["sudo","iptables","-P","FORWARD","ACCEPT"],
        ["sudo","iptables","-P","INPUT","ACCEPT"],
        ["sudo","iptables","-P","OUTPUT","ACCEPT"],
        ["sudo","ip6tables","-P","FORWARD","ACCEPT"],
        ["sudo","ip6tables","-P","INPUT","ACCEPT"],
        ["sudo","ip6tables","-P","OUTPUT","ACCEPT"],
    ]:
        subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    print("[+] Network restored.")

atexit.register(cleanup)
def _sig(s,f): sys.exit(0)
signal.signal(signal.SIGINT,_sig); signal.signal(signal.SIGTERM,_sig)

# ── ENTRY POINT ───────────────────────────────────────────────────
if __name__=='__main__':
    init_system()
    generate_wifi_profile_ios(YOUR_SSID,WIFI_PASSWORD or None)
    generate_wifi_profile_android(YOUR_SSID,WIFI_PASSWORD or None)

    own_ip=_get_own_ip()
    if own_ip:
        _cp.SERVER_IP=own_ip
        print(f"[SYSTEM] Own IP     → {own_ip}")
    else:
        print("[WARN] No IP on eth0 — run: sudo dhclient eth0")

    print(f"[SYSTEM] Own MACs   → {OWN_MACS}")
    print(f"[SYSTEM] Router MACs → {ROUTER_BSSIDS}")

    threading.Thread(target=passive_arp_monitor,daemon=True).start()
    threading.Thread(target=active_network_scanner,daemon=True).start()
    threading.Thread(target=esp32_listener,daemon=True).start()

    alert_startup(YOUR_SSID,L3_INTERFACE)
    print(f"[SYSTEM] Dashboard  → http://0.0.0.0:8000")
    print(f"[SYSTEM] Login      → http://0.0.0.0:8000/login")
    print(f"[SYSTEM] Mode       → Full blackhole (TCP+UDP+IPv6)")
    app.run(host='0.0.0.0',port=8000,threaded=True)
