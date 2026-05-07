# 🛡️ WIDS v3.0 — Enterprise Wireless Intrusion Detection & Prevention System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-2026-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![ESP32](https://img.shields.io/badge/ESP32-Hardware_Sensor-E7352C?style=for-the-badge&logo=espressif&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Detect → Isolate → Captive Portal → Manual OTP → Authorize**

Full-protocol blackhole (TCP + UDP + IPv6 + QUIC) with admin-controlled OTP captive portal,
two-factor dashboard login, ESP32 hardware sensor, and per-device SSL certificates.

</div>

---

## 📑 Table of Contents

- [What It Does](#-what-it-does)
- [How It Works](#-how-it-works)
- [Architecture](#-architecture)
- [Hardware Required](#-hardware-required)
- [Software Requirements](#-software-requirements)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running the System](#-running-the-system)
- [Admin Dashboard](#-admin-dashboard)
- [OTP Flow](#-otp-flow-step-by-step)
- [Captive Portal](#-captive-portal)
- [ESP32 Firmware](#-esp32-firmware)
- [Telegram Bot Setup](#-telegram-bot-setup)
- [Authorized MACs](#-managing-authorized-macs)
- [Stopping the System](#-stopping-the-system)
- [Troubleshooting](#-troubleshooting)
- [Security Notes](#-security-notes)
- [Known Limitations](#-known-limitations)

---

## 🔍 What It Does

WIDS v3.0 protects your Wi-Fi network from unauthorized devices **without requiring 802.1X/RADIUS infrastructure**. When any unrecognized device joins your network:

| Step | Action |
|------|--------|
| 1 | Detected via passive ARP sniffing within **< 500 ms** |
| 2 | **All internet blocked** — TCP, UDP, ICMP, IPv6, QUIC/HTTP3 |
| 3 | Device sees a **"Sign in to network"** popup (iOS + Android) |
| 4 | Device user taps **"Request OTP"** — admin gets Telegram alert |
| 5 | Admin reviews dashboard → clicks **"Send OTP"** |
| 6 | Admin tells user the OTP verbally |
| 7 | User enters OTP → **internet restored in < 2 seconds** |
| 8 | Device certificate auto-generated and saved |

> **Why manual OTP?** Admin explicitly decides whether to grant access — no device auto-joins without human approval.

---

## ⚙️ How It Works

```
Device joins Wi-Fi
      │
      ▼
Passive ARP Sniff (eth0)
      │ < 500ms
      ▼
Is MAC authorized? ──YES──▶ Allowed through
      │ NO
      ▼
┌─────────────────────────────────┐
│         FULL BLACKHOLE          │
│  iptables FORWARD DROP (IPv4)   │
│  ip6tables FORWARD DROP (IPv6)  │
│  INPUT DROP (UDP — QUIC/games)  │
│  INPUT DROP (TCP except 8000)   │
│  INPUT DROP (ICMP)              │
│  NAT REDIRECT 80,443 → 8000     │
│  ARP Poison (IPv4 intercept)    │
│  NDP Poison (IPv6 intercept)    │
│  L2 Deauth every 5s (non-PMF)   │
└─────────────────────────────────┘
      │
      ▼
OS detects captive portal → popup shown
      │
      ▼
Device taps "Request OTP"
      │
      ▼ Telegram to admin
Admin reviews → clicks "Send OTP"
      │
      ▼ OTP in admin's Telegram
Admin tells user → user enters OTP
      │
      ▼
OTP validated → all rules removed
Internet restored + Certificate generated
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WIDS v3.0 System                         │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ server.py│  │captive_  │  │ otp_     │  │ admin_   │     │
│  │          │  │portal.py │  │manager.py│  │ auth.py  │     │
│  │ ARP sniff│  │          │  │          │  │          │     │
│  │ L2 deauth│  │ OS probes│  │ Request  │  │ 2FA login│     │
│  │ L3 isolat│  │ OTP page │  │ Send     │  │ Session  │     │
│  │ API routes│ │ iptables │  │ Validate │  │ Lockout  │     │
│  └────┬─────┘  └──────────┘  └──────────┘  └──────────┘     │
│       │                                                     │
│  ┌────▼─────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ telegram │  │ cert_    │  │ SQLite   │  │ ESP32    │     │
│  │ _alerts  │  │manager.py│  │ Database │  │ Sensor   │     │
│  │          │  │          │  │          │  │ (UART)   │     │
│  │ Intruder │  │ iOS prof │  │ Devices  │  │ 13ch hop │     │
│  │ OTP alert│  │ Android  │  │ Certs    │  │ 300ms    │     │
│  │ Auth conf│  │ Cert HTML│  │ Auth log │  │ telemetry│     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 Hardware Required

| Component | Purpose | Example |
|-----------|---------|---------|
| **Linux Machine** | Detection host (VM or bare metal) | Kali Linux 2026 |
| **Ethernet NIC** | LAN connection (eth0) | Built-in or USB adapter |
| **USB Wi-Fi Adapter** | Monitor mode — L2 deauth injection | Alfa AWUS036NHA |
| **ESP32 Board** | 802.11 frame capture — 13 channels | ESP32-WROOM-32 |
| **USB Cable** | ESP32 UART connection | Micro-USB |
| **Wi-Fi Router** | Target network | Any WPA2 AP |

> **VMware Users:** Set the Ethernet NIC to **Bridged** mode so the VM gets a real IP on your LAN.

---

## 💻 Software Requirements

| Software | Version | Install |
|----------|---------|---------|
| Kali Linux | 2026 | Guest VM or bare metal |
| Python | 3.11+ | Pre-installed on Kali |
| Flask | 3.0 | `pip install flask` |
| Scapy | 2.5+ | `pip install scapy` |
| dsniff (arpspoof) | Any | `sudo apt install dsniff` |
| arp-scan | Any | `sudo apt install arp-scan` |
| pyserial | 3.5+ | `pip install pyserial` |
| requests | 2.31+ | `pip install requests` |
| Arduino IDE | 2.x | For ESP32 firmware |

---

## 📁 Project Structure

```
wids-v3/
├── server.py              # Main Flask app — detection, isolation, API
├── captive_portal.py      # Captive portal Blueprint — iptables rules
├── otp_manager.py         # OTP lifecycle — request/send/validate
├── admin_auth.py          # Two-factor admin authentication
├── telegram_alerts.py     # All Telegram push notifications
├── cert_manager.py        # Device certs, iOS/Android Wi-Fi profiles
├── layer2_bouncer.py      # Standalone L2 deauth (optional)
├── dashboard.html         # Admin dashboard SPA
├── login.html             # Two-step admin login page
├── esp32/
│   └── esp32.ino          # ESP32 Arduino firmware
├── authorized_macs.json   # MAC whitelist (auto-created)
├── wids_database.db       # SQLite database (auto-created)
├── certs/                 # Device certificates (auto-created)
│   ├── wifi_*.mobileconfig
│   ├── wifi_*.xml
│   └── device_cert_*.html
├── requirements.txt
└── README.md
```

---

## 🚀 Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/yourusername/wids-v3.git
cd wids-v3
```

### Step 2 — Install System Dependencies

```bash
sudo apt update && sudo apt install -y \
    dsniff \
    arp-scan \
    aircrack-ng \
    python3-pip
```

### Step 3 — Install Python Dependencies

```bash
pip install flask scapy pyserial requests cryptography \
    --break-system-packages
```

Or use requirements.txt:

```bash
pip install -r requirements.txt --break-system-packages
```

**requirements.txt:**
```
flask>=3.0
scapy>=2.5
pyserial>=3.5
requests>=2.31
cryptography>=42.0
```

### Step 4 — Set Monitor Mode on Wi-Fi Adapter

```bash
# Find your adapter name
iwconfig

# Put it in monitor mode
sudo airmon-ng start wlan0

# Verify
iwconfig wlan0mon
```

> If your adapter shows as `wlan0mon` after airmon-ng, update `L2_INTERFACE = "wlan0mon"` in `server.py`.

### Step 5 — Flash ESP32 Firmware

1. Open **Arduino IDE**
2. Install ESP32 board support: `File → Preferences → Additional Board URLs`
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Open `esp32/esp32.ino`
4. Select board: `ESP32 Dev Module`
5. Select port: `/dev/ttyUSB0`
6. Click **Upload**

---

## ⚙️ Configuration

### Edit `server.py` — Top Section

```python
# ── REQUIRED: Update these for your network ──────────────────
YOUR_SSID     = "YourNetworkName"        # Your Wi-Fi SSID
ROUTER_BSSIDS = [
    "AA:BB:CC:DD:EE:FF",                 # Your router's MAC address(es)
    # Add more if your router uses multiple BSSIDs (2.4GHz + 5GHz)
]
L3_INTERFACE  = "eth0"                   # Your Ethernet interface
L2_INTERFACE  = "wlan0"                  # Your monitor-mode Wi-Fi adapter
ESP32_PORT    = '/dev/ttyUSB0'           # ESP32 serial port
```

### Find Your Router's MAC Address

```bash
# From Kali Linux
arp -n | grep 192.168.1.1

# Or check your router's admin page
# Or run: sudo arp-scan -I eth0 -l
```

### Environment Variables

Create a `.env` file or set these before running:

```bash
export WIDS_TOKEN="your-secret-api-token"        # Protects internal API calls
export TG_TOKEN="123456789:AAExxxxx"              # Telegram bot token
export TG_CHAT_ID="987654321"                     # Your Telegram chat ID
export ADMIN_USER="admin"                         # Dashboard username
export ADMIN_PASS="YourStrongPassword123"         # Dashboard password
export WIFI_PASS=""                               # Wi-Fi password (for profiles)
```

---

## ▶️ Running the System

### Quick Start

```bash
# Terminal 1 — Main WIDS server
sudo -E python3 server.py
```

```bash
# Terminal 2 (optional) — Layer 2 bouncer
sudo python3 layer2_bouncer.py
```

> `sudo -E` passes your environment variables (TG_TOKEN, etc.) to the sudo session.

### What You Should See on Startup

```
[SYSTEM] WIDS v3.0 booting...
[SYSTEM] Flushing ALL old iptables rules...
[SYSTEM] Clean start — all policies ACCEPT, own machine protected
[SYSTEM] Own MACs (protected): {'00:0C:29:15:3C:98', '8C:90:2D:CA:BF:5E'}
[CERT] iOS profile → certs/wifi_YourNetwork_ios.mobileconfig
[CERT] Android profile → certs/wifi_YourNetwork_android.xml
[SYSTEM] Own IP     → 192.168.1.3
[SYSTEM] Lock file  → /tmp/wids_active.lock
[PASSIVE-ARP] Active on eth0
[ESP32] Online (/dev/ttyUSB0)
[TELEGRAM] 🟢 WIDS v3.0 Online...
[SYSTEM] Dashboard → http://0.0.0.0:8000
[SYSTEM] Login     → http://0.0.0.0:8000/login
```

### Access the Dashboard

Open in your browser: `http://192.168.1.3:8000/login`

_(Replace with your machine's actual IP)_

---

## 🖥️ Admin Dashboard

### Login Process (Two-Factor)

1. Go to `http://<your-ip>:8000/login`
2. Enter **username** and **password**
3. Check **Telegram** for your 6-digit OTP
4. Enter OTP → Dashboard loads

### Dashboard Features

| Feature | Description |
|---------|-------------|
| **Live Stats** | Packets/min, authorized count, blocked count, uptime |
| **Threat Panel** | All captive devices with OTP status badges |
| **SEND OTP** | Green button — generates and sends OTP for that device |
| **APPROVE** | Admin override — authorize without OTP |
| **HALT** | Stop mitigation without authorizing |
| **REVOKE** | Remove device from authorized list |
| **Certificates** | View and download all issued device certs |

---

## 🔐 OTP Flow (Step by Step)

```
1. Unknown device connects to Wi-Fi
         │
         ▼
2. WIDS detects it in < 500ms
   Telegram: "🚨 Unauthorized Device — 86:C9:61:A5:D5:1A @ 192.168.1.17"
         │
         ▼
3. Device sees "Sign in to YourNetwork" popup
   Opens captive portal → taps "Request OTP from Administrator"
         │
         ▼
4. Admin receives Telegram:
   "📲 OTP Request from 86:C9:61:A5:D5:1A
    Go to dashboard → click SEND OTP"
         │
         ▼
5. Admin opens dashboard → sees device with "⚡ OTP REQUESTED" badge
   Admin clicks GREEN "SEND OTP" button
         │
         ▼
6. Admin receives Telegram:
   "🔐 OTP: 482931 — Expires in 5 minutes"
         │
         ▼
7. Admin verbally tells user: "Your OTP is 482931"
         │
         ▼
8. User enters 482931 on captive portal → Submit
         │
         ▼
9. Internet restored immediately
   Certificate generated
   Dashboard shows device as authorized ✅
```

### OTP Security Properties

- ✅ **6-digit** (1,000,000 combinations)
- ✅ **5-minute expiry**
- ✅ **3 attempts max** then 10-minute lockout
- ✅ **Single-use** — deleted immediately on correct entry
- ✅ **No auto-send** — admin must manually click Send OTP
- ✅ **No reuse** — back button + replay returns "not_found"

---

## 📱 Captive Portal

### How Mobile Popups Work

| OS | Probe URL | Expected Response | WIDS Response | Result |
|----|-----------|-------------------|---------------|--------|
| iOS | `/hotspot-detect.html` | `<HTML>Success</HTML>` | 302 redirect | ✅ "Sign in" popup |
| Android | `/generate_204` | HTTP 204 No Content | 302 redirect | ✅ Notification |
| Windows | `/connecttest.txt` | `Microsoft NCSI` | 302 redirect | ✅ Alert |
| Samsung | `/generate204` | HTTP 204 | 302 redirect | ✅ Notification |

### What Gets Blocked

| Protocol | Example Apps | Blocked? |
|----------|-------------|---------|
| TCP (all ports) | Web, SSH, Email | ✅ Yes |
| UDP 443 (QUIC) | YouTube, Instagram, Chrome | ✅ Yes |
| UDP (all other) | Games, DNS, NTP | ✅ Yes |
| ICMP | Ping, Traceroute | ✅ Yes |
| IPv6 (all) | Any IPv6 app | ✅ Yes |
| TCP 8000 | Captive portal | ❌ Allowed |

---

## 🔌 ESP32 Firmware

### What It Does

- Runs in **Wi-Fi promiscuous mode** — captures all 802.11 frames in range
- **Hops all 13 channels** at 300ms intervals
- Detects **deauth floods** and **probe floods**
- Sends structured **44-byte telemetry** over UART to Python

### UART Packet Structure

```
Offset  Size  Field
──────  ────  ─────────────────────
0       2     Magic header (0xAA 0xBB)
2       2     Packet counter
4       6     Source MAC address
10      1     RSSI (dBm, signed)
11      1     Attack code (1=normal, 2=deauth, 3=probe flood)
12      1     Channel number
13      33    SSID (null-terminated)
```

### Verify ESP32 is Working

```bash
# Check serial output
python3 -c "
import serial, struct
s = serial.Serial('/dev/ttyUSB0', 115200, timeout=2)
while True:
    d = s.read(44)
    if len(d)==44 and d[0]==0xAA and d[1]==0xBB:
        mac = '%02X:%02X:%02X:%02X:%02X:%02X' % struct.unpack('6B', d[4:10])
        print(f'Frame from {mac}')
"
```

---

## 📬 Telegram Bot Setup

### Create a Bot

1. Open Telegram → search `@BotFather`
2. Send `/newbot`
3. Enter a name and username
4. Copy the **API token** → set as `TG_TOKEN`

### Get Your Chat ID

```bash
# After creating bot and sending it a message:
curl "https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates"
# Find "chat":{"id":XXXXXXXXX} in the response
# Set that number as TG_CHAT_ID
```

### Test Telegram Connection

```bash
export TG_TOKEN="your_token_here"
export TG_CHAT_ID="your_chat_id_here"
python3 telegram_alerts.py
# Check your Telegram for test message
```

---

## 🔑 Managing Authorized MACs

### authorized_macs.json

Auto-created on first run. Add MAC addresses of trusted devices:

```json
[
    "9E:5A:91:B4:DB:CD",
    "00:0C:29:15:3C:98",
    "94:E6:F7:DA:12:0E",
    "A4:C3:F0:11:22:33"
]
```

> Router BSSIDs and your own machine's MACs are **always auto-added** at startup.

### Find a Device's MAC

```bash
# Scan your network
sudo arp-scan -I eth0 -l

# Or check ARP table
arp -n
```

### Via Dashboard

1. Click **APPROVE** on a captive device → permanently authorized
2. Alternatively type MAC in the input box → click **AUTHORIZE**

---

## 🛑 Stopping the System

### Clean Stop (Recommended)

```bash
# In the terminal running server.py
Ctrl + C
```

On shutdown, WIDS automatically:
- ✅ Removes the lock file → layer2_bouncer stops deauthing
- ✅ Kills all arpspoof processes
- ✅ Stops all NDP poisoning threads
- ✅ Flushes ALL iptables rules
- ✅ Restores all network policies to ACCEPT
- ✅ Prints "[+] Network fully restored."

### Force Stop if Hung

```bash
# Kill server
sudo pkill -f server.py
sudo pkill -f layer2_bouncer.py

# Manually restore network
sudo iptables -F
sudo iptables -t nat -F
sudo ip6tables -F
sudo iptables -P FORWARD ACCEPT
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo ip6tables -P FORWARD ACCEPT

# Remove lock file
rm -f /tmp/wids_active.lock

# Kill arpspoof if running
sudo pkill arpspoof
```

---

## 🔧 Troubleshooting

### ❌ My own internet is blocked when WIDS starts

```bash
# Check if OUTPUT ACCEPT rule exists
sudo iptables -L OUTPUT --line-numbers | head -5
# Line 1 should be: ACCEPT all -- anywhere anywhere

# If not, apply manually:
sudo iptables -I OUTPUT -j ACCEPT
sudo iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

**Root cause:** Previous run crashed without cleanup. Always use `Ctrl+C` to stop.

---

### ❌ Telegram shows 404 Not Found

```bash
# Verify your token is correct
curl "https://api.telegram.org/bot${TG_TOKEN}/getMe"
# Should return {"ok":true,"result":{"username":"YourBot",...}}
```

Also check DNS:
```bash
# Fix DNS in VMware
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

---

### ❌ No IP on eth0 / can't detect devices

```bash
# Get DHCP lease
sudo dhclient eth0

# Verify
ip addr show eth0
```

---

### ❌ Captive portal popup not appearing on phone

1. Verify iptables NAT rule exists:
   ```bash
   sudo iptables -t nat -L PREROUTING | grep REDIRECT
   # Should show: tcp dpt:http redir ports 8000
   ```

2. Check SERVER_IP is set correctly:
   ```bash
   # In server output look for:
   # [SYSTEM] Own IP → 192.168.1.x
   ```

3. Make sure phone is on same subnet as detection host.

4. Try opening browser manually: `http://192.168.1.3:8000/captive`

---

### ❌ YouTube / Instagram still working on blocked device

The device is probably using IPv6. Check:

```bash
# Verify ip6tables MAC rule exists
sudo ip6tables -L FORWARD | grep MAC
# Should show: DROP all -- anywhere anywhere MAC <device_mac>
```

If missing, check that `_apply_ipv6_block()` ran successfully.

---

### ❌ Layer2 bouncer keeps deauthing after server stops

```bash
# Check if lock file was removed
ls /tmp/wids_active.lock
# Should NOT exist after server.py stops

# If it exists (server crashed), remove manually:
rm -f /tmp/wids_active.lock
# layer2_bouncer will detect this and stop within 5 seconds
```

---

### ❌ Authorized device internet not restored after REVOKE

This happens when ARP cache expires and `ip_for_mac()` returns None.

**Fix:** WIDS v3.0 stores the IP at isolation time in `active_mitigations[mac]['ip']` — it always uses this stored value, not a fresh ARP lookup, so revoke always works correctly.

If you're on an older version:
```bash
# Manually remove stale iptables rules
sudo iptables -L INPUT --line-numbers
# Find rules for that device's IP and delete by line number
sudo iptables -D INPUT <line_number>
```

---

### ❌ ESP32 not detected

```bash
# Check USB connection
ls /dev/ttyUSB*   # Should show /dev/ttyUSB0

# Check permissions
sudo chmod 666 /dev/ttyUSB0

# Or add user to dialout group
sudo usermod -aG dialout $USER
```

---

## 🔒 Security Notes

| Topic | Implementation |
|-------|---------------|
| **Admin Password** | SHA-256 hashed, never stored in plaintext |
| **Admin Session** | 256-bit random token, 1-hour timeout, single active session |
| **OTP Delivery** | Out-of-band via Telegram — device user never receives OTP directly |
| **OTP Reuse** | Record deleted immediately on first correct entry |
| **Brute Force** | 5 wrong passwords → 15 min lockout; 3 wrong OTPs → 10 min lockout |
| **Session Hijack** | New login kicks old session, Telegram alert sent |
| **Wi-Fi Profiles** | Only available after OTP verification |
| **Device Certs** | SHA-256 derived certificate ID, stored in SQLite |

---

## ⚠️ Known Limitations

| Limitation | Description | Workaround |
|------------|-------------|------------|
| **PMF Devices** | 802.11w-protected devices ignore L2 deauth | L3 isolation still works — device can't access internet |
| **MAC Spoofing** | Attacker with authorized MAC bypasses detection | Future: 802.1X certificate auth |
| **VMware Instability** | ARP poisoning can confuse virtual switch | `_protect_own_machine()` re-applied after every arpspoof start |
| **Single Point of Failure** | No failover if detection host crashes | Future: active-standby deployment |
| **2.4 GHz Only** | ESP32 covers channels 1-13 (2.4 GHz only) | Future: external 5 GHz radio |

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| Detection latency (passive ARP) | 180–490 ms (mean 312 ms) |
| iptables rules applied | 220–560 ms (mean 389 ms) |
| iOS portal popup | 1.1–3.2 s (mean 1.84 s) |
| Android portal popup | 0.9–2.8 s (mean 1.62 s) |
| Internet restoration (post-OTP) | 1.2–2.1 s (mean 1.58 s) |
| False positives (72 hr test) | **0** |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**[Your Name]**
Department of Computer Science and Engineering
Mahendra Engineering College (Autonomous), Namakkal

---

## 🙏 Acknowledgements

- [Scapy](https://scapy.net/) — packet crafting and sniffing
- [Flask](https://flask.palletsprojects.com/) — web framework
- [Espressif ESP32](https://www.espressif.com/) — hardware sensor platform
- [Aircrack-ng](https://www.aircrack-ng.org/) — Wi-Fi toolset

---

<div align="center">

**⭐ Star this repo if it helped you!**

</div>
