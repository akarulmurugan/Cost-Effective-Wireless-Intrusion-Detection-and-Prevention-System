#!/usr/bin/env python3
"""cert_manager.py — WIDS v3.0 certificate and Wi-Fi profile generation."""
import os, hashlib, datetime, uuid, time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(BASE_DIR, "certs")
os.makedirs(CERT_DIR, exist_ok=True)

# ── HTTPS TLS Certificate ─────────────────────────────────────────
def generate_https_cert(hostname="wids.local", ip="127.0.0.1",
                         org="WIDS Security", days=825):
    cert_path = os.path.join(CERT_DIR, "wids_dashboard.crt")
    key_path  = os.path.join(CERT_DIR, "wids_dashboard.key")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    try:
        import ipaddress
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509 import DNSName, IPAddress as X509IP
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        san = [DNSName(hostname), DNSName("localhost")]
        try: san.append(X509IP(ipaddress.IPv4Address(ip)))
        except Exception: pass
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() +
                                 datetime.timedelta(days=days))
                .add_extension(x509.SubjectAlternativeName(san), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                               critical=True)
                .add_extension(x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(key, hashes.SHA256()))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[CERT] HTTPS cert generated → {cert_path}")
    except ImportError:
        print("[CERT] cryptography not installed — HTTPS cert skipped")
    return cert_path, key_path

def get_ssl_context():
    c = os.path.join(CERT_DIR, "wids_dashboard.crt")
    k = os.path.join(CERT_DIR, "wids_dashboard.key")
    if not os.path.exists(c):
        generate_https_cert()
    return (c, k)

# ── iOS Wi-Fi Profile (.mobileconfig) ────────────────────────────
def generate_wifi_profile_ios(ssid, password=None):
    pid  = str(uuid.uuid4()).upper()
    plid = str(uuid.uuid4()).upper()
    fn   = os.path.join(CERT_DIR,
                        f"wifi_{ssid.replace(' ','_')}_ios.mobileconfig")
    sec = (f"<key>EncryptionType</key><string>WPA</string>"
           f"<key>Password</key><string>{password}</string>"
           if password else
           "<key>EncryptionType</key><string>None</string>")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>AutoJoin</key><true/>
      <key>HIDDEN_NETWORK</key><false/>
      <key>PayloadDescription</key>
      <string>WIDS Authorized Wi-Fi — {ssid}</string>
      <key>PayloadDisplayName</key>
      <string>Wi-Fi ({ssid})</string>
      <key>PayloadIdentifier</key>
      <string>com.wids.wifi.{plid}</string>
      <key>PayloadType</key>
      <string>com.apple.wifi.managed</string>
      <key>PayloadUUID</key>
      <string>{plid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>ProxyType</key><string>None</string>
      <key>SSID_STR</key><string>{ssid}</string>
      {sec}
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>WIDS Network Security Profile</string>
  <key>PayloadDisplayName</key>
  <string>WIDS — {ssid}</string>
  <key>PayloadIdentifier</key>
  <string>com.wids.profile.{pid}</string>
  <key>PayloadOrganization</key>
  <string>WIDS Security System</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{pid}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>"""
    with open(fn, "w") as f:
        f.write(xml)
    print(f"[CERT] iOS profile → {fn}")
    return fn

# ── Android Wi-Fi Profile (.xml) ──────────────────────────────────
def generate_wifi_profile_android(ssid, password=None):
    fn = os.path.join(CERT_DIR,
                      f"wifi_{ssid.replace(' ','_')}_android.xml")
    if password:
        auth = (f"<authentication>WPA2PSK</authentication>"
                f"<encryption>AES</encryption>"
                f"<useOneX>false</useOneX>"
                f"<sharedKey><keyType>passPhrase</keyType>"
                f"<protected>false</protected>"
                f"<keyMaterial>{password}</keyMaterial></sharedKey>")
    else:
        auth = ("<authentication>open</authentication>"
                "<encryption>none</encryption>"
                "<useOneX>false</useOneX>")
    xml = (f'<?xml version="1.0"?>'
           f'<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
           f'<n>{ssid}</n><SSIDConfig><SSID><n>{ssid}</n></SSID>'
           f'<nonBroadcast>false</nonBroadcast></SSIDConfig>'
           f'<connectionType>ESS</connectionType>'
           f'<connectionMode>auto</connectionMode>'
           f'<MSM><security>{auth}</security></MSM></WLANProfile>')
    with open(fn, "w") as f:
        f.write(xml)
    print(f"[CERT] Android profile → {fn}")
    return fn

# ── Device Authorization Certificate (HTML) ───────────────────────
def generate_device_certificate(mac, ip, device_name,
                                 issued_by="WIDS Admin",
                                 network_name="Office Network"):
    cert_id = hashlib.sha256(
        f"{mac}{ip}{time.time()}".encode()).hexdigest()[:12].upper()
    issued  = datetime.datetime.now().strftime("%d %B %Y  %H:%M:%S")
    expires = (datetime.datetime.now() +
               datetime.timedelta(days=365)).strftime("%d %B %Y")
    fn = os.path.join(CERT_DIR,
                      f"device_cert_{mac.replace(':','')}.html")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WIDS Certificate — {mac}</title>
<style>
body{{margin:0;padding:40px;background:#0b1120;
  font-family:'Courier New',monospace;color:#c8e8f0;
  display:flex;justify-content:center;align-items:center;min-height:100vh;}}
.cert{{background:#060f1e;border:2px solid #00ffe0;border-radius:12px;
  max-width:680px;width:100%;padding:48px 52px;
  box-shadow:0 0 40px rgba(0,255,224,0.15);}}
.seal{{text-align:center;margin-bottom:22px;}}
h1{{font-size:20px;color:#00ffe0;letter-spacing:4px;text-align:center;
  text-transform:uppercase;border-bottom:1px solid rgba(0,255,224,.2);
  padding-bottom:14px;margin-bottom:8px;}}
.sub{{text-align:center;font-size:10px;color:#3a6070;letter-spacing:3px;margin-bottom:32px;}}
.row{{display:flex;justify-content:space-between;padding:11px 0;
  border-bottom:1px solid rgba(0,255,224,.07);}}
.lbl{{font-size:10px;color:#3a6070;letter-spacing:2px;text-transform:uppercase;}}
.val{{font-size:12px;color:#00bfaa;font-weight:bold;}}
.status{{text-align:center;margin-top:28px;}}
.badge{{display:inline-block;background:rgba(0,255,136,0.1);color:#00ff88;
  border:1px solid rgba(0,255,136,0.3);padding:4px 16px;border-radius:4px;
  font-size:10px;letter-spacing:2px;text-transform:uppercase;}}
.cid{{text-align:center;margin-top:16px;font-size:10px;
  color:rgba(0,255,224,.15);letter-spacing:2px;}}
@media print{{body{{background:#fff;color:#000;}}
  .cert{{border-color:#000;background:#fff;box-shadow:none;}}
  h1,.val{{color:#000;}}}}
</style>
</head>
<body>
<div class="cert">
  <div class="seal">
    <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
      <circle cx="32" cy="32" r="30" stroke="#00ffe0"
              stroke-width="1" opacity=".3"/>
      <circle cx="32" cy="32" r="24" stroke="#00ffe0" stroke-width="1"/>
      <path d="M32 12l4 12h13l-10 8 4 12-11-8-11 8 4-12L15 24h13Z"
            stroke="#00ffe0" stroke-width="1.2"
            stroke-linejoin="round" fill="none"/>
    </svg>
  </div>
  <h1>Network Authorization Certificate</h1>
  <p class="sub">WIRELESS INTRUSION DETECTION &amp; PREVENTION SYSTEM</p>
  <div class="row">
    <span class="lbl">Certificate ID</span>
    <span class="val">{cert_id}</span>
  </div>
  <div class="row">
    <span class="lbl">Device Name</span>
    <span class="val">{device_name}</span>
  </div>
  <div class="row">
    <span class="lbl">MAC Address</span>
    <span class="val">{mac}</span>
  </div>
  <div class="row">
    <span class="lbl">IP Address</span>
    <span class="val">{ip}</span>
  </div>
  <div class="row">
    <span class="lbl">Authorized Network</span>
    <span class="val">{network_name}</span>
  </div>
  <div class="row">
    <span class="lbl">Issued On</span>
    <span class="val">{issued}</span>
  </div>
  <div class="row">
    <span class="lbl">Valid Until</span>
    <span class="val">{expires}</span>
  </div>
  <div class="row">
    <span class="lbl">Authorized By</span>
    <span class="val">{issued_by}</span>
  </div>
  <div class="status">
    <span class="badge">✓ Authorized</span>
  </div>
  <div class="cid">CERT-ID: {cert_id} · WIDS v3.0</div>
</div>
</body>
</html>"""
    with open(fn, "w") as f:
        f.write(html)
    print(f"[CERT] Device cert → {fn} (IP: {ip})")
    return fn, cert_id

def get_cert_path(mac):
    fn = os.path.join(CERT_DIR,
                      f"device_cert_{mac.replace(':','')}.html")
    return fn if os.path.exists(fn) else None

def get_wifi_profile_path(ssid, platform):
    ext = "mobileconfig" if platform == "ios" else "xml"
    return os.path.join(CERT_DIR,
                        f"wifi_{ssid.replace(' ','_')}_{platform}.{ext}")
