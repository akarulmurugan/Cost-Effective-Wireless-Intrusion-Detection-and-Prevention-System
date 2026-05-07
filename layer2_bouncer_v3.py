#!/usr/bin/env python3
"""
ENTERPRISE WIDS — LAYER 2 RADIO ENFORCER v3.0
New: channel hopping — monitors all 2.4 GHz channels
"""
from scapy.all import sniff,RadioTap,Dot11,Dot11Deauth,sendp
import requests,json,time,os,threading,subprocess

KALI_INTERFACE="wlan0"
SERVER_URL="http://127.0.0.1:8000/api/packet"
API_TOKEN=os.environ.get("WIDS_TOKEN","wids-change-this-token")
HEADERS={"X-WIDS-Token":API_TOKEN,"Content-Type":"application/json"}
ROUTER_BSSIDS=["A0:91:CA:3C:35:9A","A6:91:CA:3C:35:9A","A0:91:CA:3C:35:91"]
BASE_DIR=os.path.dirname(os.path.abspath(__file__))
AUTH_FILE=os.path.join(BASE_DIR,"authorized_macs.json")
DEAUTH_COOLDOWN=3.0
HOP_CHANNELS=[1,2,3,4,5,6,7,8,9,10,11,12,13]
HOP_INTERVAL=0.3   # seconds per channel

# Whitelist cache
_wl=set(); _wl_ts=0.0; _wl_lock=threading.Lock()
def get_auth_macs():
    global _wl,_wl_ts
    now=time.time()
    with _wl_lock:
        if now-_wl_ts<5.0: return _wl
        try:
            if os.path.exists(AUTH_FILE):
                with open(AUTH_FILE) as f: _wl=set(json.load(f))
                _wl_ts=now
        except Exception as e: print(f"[!] Whitelist: {e}")
        return _wl

# Deauth cooldown
_cd={}; _cd_lock=threading.Lock()
def _on_cd(mac):
    with _cd_lock:
        if time.time()-_cd.get(mac,0)<DEAUTH_COOLDOWN: return True
        _cd[mac]=time.time()
    return False

# Channel hopper
_hop_stop=threading.Event()
_hop_pin=threading.Event()
_current_ch=6

def _set_ch(ch):
    global _current_ch
    subprocess.run(["sudo","iwconfig",KALI_INTERFACE,"channel",str(ch)],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    _current_ch=ch

def _hop_loop():
    idx=0
    while not _hop_stop.is_set():
        if _hop_pin.is_set(): time.sleep(0.1); continue
        _set_ch(HOP_CHANNELS[idx%len(HOP_CHANNELS)])
        idx+=1
        time.sleep(HOP_INTERVAL)

def _fire_deauth(client_mac,router_mac):
    if _on_cd(client_mac): return
    # Pin to current channel so deauth lands correctly
    ch=_current_ch; _hop_pin.set()
    try:
        pkt=(RadioTap()/Dot11(addr1=client_mac,addr2=router_mac,addr3=router_mac)/Dot11Deauth(reason=7))
        print(f"[L2] Deauth -> {client_mac} via {router_mac} ch{ch}")
        sendp(pkt,iface=KALI_INTERFACE,count=10,inter=0.05,verbose=0)
    finally:
        _hop_pin.clear()

def _alert_server(client_mac,target_network):
    try:
        requests.post(SERVER_URL,json={'mac':client_mac,'attack_code':2,
                      'channel':_current_ch,'ssid':target_network},
                      headers=HEADERS,timeout=0.5)
    except: pass

def handle_packet(pkt):
    if not pkt.haslayer(Dot11): return
    a1=(pkt.addr1 or "").upper()
    a2=(pkt.addr2 or "").upper()
    if a1 not in ROUTER_BSSIDS and a2 not in ROUTER_BSSIDS: return
    router_mac=a1 if a1 in ROUTER_BSSIDS else a2
    client_mac=a2 if a1 in ROUTER_BSSIDS else a1
    if not client_mac or client_mac in ("FF:FF:FF:FF:FF:FF","") or client_mac in ROUTER_BSSIDS: return
    if client_mac in get_auth_macs(): return
    net="Guest Network" if "A6" in router_mac else "Main Network"
    print(f"\n[RADIO ALERT] Intruder {client_mac} on {net}")
    threading.Thread(target=_fire_deauth,args=(client_mac,router_mac),daemon=True).start()
    threading.Thread(target=_alert_server,args=(client_mac,net),daemon=True).start()

print("="*60)
print("LAYER 2 RADIO ENFORCER v3.0")
print(f"Interface  : {KALI_INTERFACE}  (monitor mode)")
print(f"Channels   : {HOP_CHANNELS} @ {HOP_INTERVAL}s each")
print(f"Defending  : {ROUTER_BSSIDS}")
print("="*60)

# Start channel hopper
threading.Thread(target=_hop_loop,daemon=True).start()
print(f"[HOP] Channel hopper started — {len(HOP_CHANNELS)} channels @ {HOP_INTERVAL}s each")

try:
    sniff(iface=KALI_INTERFACE,prn=handle_packet,store=0)
except KeyboardInterrupt:
    print("\n[*] Layer 2 Enforcer stopped.")
    _hop_stop.set()
except Exception as e:
    print(f"\n[FATAL] {e}")
    print(f"[?] Is '{KALI_INTERFACE}' in monitor mode? Try: sudo airmon-ng start wlan0")
