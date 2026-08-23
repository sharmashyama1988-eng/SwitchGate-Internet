# 🌐 SwitchGate: The No-Code Network Gateway & Remote Control

> **SwitchGate** एक क्रांतिकारी, नेटवर्क-लेवल डिजिटल पेनकिलर (Digital Painkiller) है जो आपके घर या ऑफिस के पूरे इंटरनेट को एक साधारण बिजली के बोर्ड वाले **ON/OFF स्विच** में बदल देता है।

---

## ⚡ Core Features & Capabilities

1. **शून्य-जटिलता डैशबोर्ड (Zero-Configuration UI):**
   - No confusing IP or MAC address clutter.
   - Automatically detects device manufacturers (Apple, Samsung, LG, Sony, Xiaomi, Fire TV, PlayStation, IoT) and names them cleanly (*"Papa's iPhone"*, *"Living Room OLED TV"*, *"Gaming Console"*).

2. **रियल-टाइम नेटवर्क रिमोट (Instant ON/OFF Switch):**
   - 1-Click cut off and restore with sub-second (<10ms) latency.
   - Dual-engine: Universal ARP Spoofing + System Firewall (`iptables` / `netsh`).

3. **विज्ञापन और ट्रैकर क्लीनर (Ad-Purge Shield):**
   - Built-in DNS Sinkhole on UDP 53/5353.
   - Destroys Smart TV telemetry, mobile ads, and tracker scripts in thin air before they reach your screens.

4. **नेटवर्क लोड बूस्टर (Turbo Bandwidth Maximizer):**
   - Select a priority device (e.g. 4K Streaming or Competitive Gaming PC) and temporarily throttle background leechers.

5. **इमरजेंसी पैनिक लॉक (Emergency Panic Switch):**
   - 1-Click lockdown: Immediately drops internet to all connected devices in your home during emergencies or focused work sessions.

6. **स्लीप टाइमर और बेडटाइम शेड्यूल (Bedtime Cutoff):**
   - Set 15m, 30m, 1h auto-cutoff countdowns or recurring night bedtime schedules for kids' tablets and Smart TVs.

---

## 🛠️ Project Structure

```
switchgate/
├── backend/
│   ├── config.py              # Auto-detection for Gateway, Subnet & Interface
│   ├── database.py            # SQLite WAL-mode persistent database
│   ├── main.py                # FastAPI app & Real-Time WebSocket Hub
│   ├── core/
│   │   ├── scanner.py         # Multi-stage ARP sweep, NetBIOS & hostname resolver
│   │   ├── blocker.py         # Sub-second ARP poisoning & firewall dropper
│   │   ├── dns_sinkhole.py    # Ad-Purge DNS sinkhole engine
│   │   ├── traffic_monitor.py # Real-time bandwidth calculator
│   │   └── oui_database.py    # Offline MAC OUI vendor & category resolver
│   └── routers/
│       ├── devices.py         # Device switching & turbo endpoints
│       ├── network.py         # Network diagnostics & stats
│       ├── adblock.py         # Ad-Purge rules & blocked telemetry
│       └── schedules.py       # Sleep timers & recurring bedtime rules
├── frontend/
│   ├── index.html             # Cyber Obsidian Master Dashboard
│   ├── css/
│   │   └── style.css          # Neumorphic toggle switches & glowing glassmorphism
│   └── js/
│       ├── app.js             # Master frontend UI controller
│       ├── websocket.js       # Auto-reconnecting WebSocket sync
│       ├── charts.js          # 60 FPS HTML5 Canvas real-time throughput graph
│       └── components.js      # Web Audio API sound synthesizer & modals
├── data/                      # Persistent SQLite DB
├── run.py                     # Universal multiplatform launcher
├── start.bat                  # 1-Click Windows launcher
├── start.sh                   # 1-Click Linux / Raspberry Pi launcher
└── requirements.txt           # Python dependencies
```

---

## 🚀 Quick Start (1-Click Run)

### On Windows:
Double-click `start.bat` or run:
```powershell
python run.py
```

### On Linux / Raspberry Pi:
```bash
sudo chmod +x start.sh
sudo ./start.sh
```

The web dashboard will automatically launch at **`http://localhost:8000`**.

---

## 🔒 Privileges & Safe Fallback
- When run as **Administrator / Root**, SwitchGate unlocks full raw socket ARP spoofing power and native kernel firewall drops.
- When run as a **standard user**, it operates in safe simulation/local mode with rich live device telemetry and responsive UI controls.
