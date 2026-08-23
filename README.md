<div align="center">

<img src="assets/Square310x310Logo.png" width="128" alt="SwitchGate Internet Logo" />

# ⚡ SwitchGate Internet

### The Ultimate High-Performance Network Gateway & Remote Control for Windows

[![Microsoft Store](https://img.shields.io/badge/Microsoft%20Store-Download%20Free-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)](https://apps.microsoft.com/detail/9P5GQ7Z98MPV?hl=en-us&gl=IN&ocid=pdpshare)
[![Windows 10/11](https://img.shields.io/badge/Windows%2010%20%2F%2011-Official%20MSIX-0078D4?style=for-the-badge&logo=windows11&logoColor=white)](https://apps.microsoft.com/detail/9P5GQ7Z98MPV?hl=en-us&gl=IN&ocid=pdpshare)
[![Version](https://img.shields.io/badge/Version-2.0.2%20(Store%20Edition)-00f5ff?style=for-the-badge)](https://apps.microsoft.com/detail/9P5GQ7Z98MPV?hl=en-us&gl=IN&ocid=pdpshare)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)](LICENSE)

<br/>

[![Get it from Microsoft](https://img.shields.io/badge/🛒_GET_IT_FROM-MICROSOFT_STORE-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)](https://apps.microsoft.com/detail/9P5GQ7Z98MPV?hl=en-us&gl=IN&ocid=pdpshare)

**SwitchGate Internet** is officially published on the **Microsoft Store** for Windows 10 & Windows 11!

[**👉 Click Here to Get SwitchGate Internet Free on Microsoft Store 👈**](https://apps.microsoft.com/detail/9P5GQ7Z98MPV?hl=en-us&gl=IN&ocid=pdpshare)

---

**Take complete control of your entire home or office network — from a single, intuitive cyber-dashboard.**

</div>

---

## 🌟 Overview

**SwitchGate Internet** turns your local Wi-Fi / Ethernet network into an interactive, hardware-style master control panel. No router login required. No manual IP address juggling. No complex network configuration.

Think of it as a **smart digital breaker board** for your entire network:
- Every connected device gets an instant **ON / OFF switch**.
- Flip it OFF → Their internet connection drops instantly (<10ms).
- Flip it ON → Connected again immediately.

> Engineered with **FastAPI + Microsoft WebView2 (EdgeChromium) + Scapy ARP Engine + DNS Sinkhole + Rust-accelerated Kernel Interceptor**.

---

## ⚡ Key Highlights & Features

| Feature | Description |
| :--- | :--- |
| **🔌 Instant 1-Click Internet Switch** | Cut off or restore internet for any device (phones, TVs, gaming consoles, PCs) with sub-second response time. |
| **🔍 Zero-Config Device Discovery** | Smart Vendor OUI analysis detects Apple, Samsung, Sony, LG, Xiaomi, FireTV, PlayStation, Xbox, and IoT devices with custom icons. |
| **🛡️ Ad-Purge & Telemetry Shield** | Built-in UDP 53/5353 DNS Sinkhole blocks smart TV tracking, aggressive mobile ads, and telemetry pings network-wide. |
| **🚀 Turbo Bandwidth Priority** | Prioritize gaming PCs or 4K streams while throttling background bandwidth hogs automatically. |
| **🚨 Emergency Panic Lockdown** | One-click emergency lockdown cuts internet across all network devices instantly. |
| **🌙 Bedtime & Sleep Timers** | Set countdown timers (15m, 30m, 1h, custom) or nightly recurring cutoff schedules for kids' devices. |
| **📊 Real-Time 60 FPS Telemetry** | Live animated bandwidth charts, ping latency, packet throughput, and threat alerts via low-latency WebSocket. |
| **🔒 100% Local & Private** | Zero cloud tracking. No data collection. All network processing stays 100% on your local machine. |

---

## 🖥️ Cyber Obsidian User Interface

> *Glassmorphism cyber UI with real-time hardware telemetry and responsive multi-touch controls*

| Dashboard Telemetry | Device Manager | Analytics & Logs |
|:-------------------:|:--------------:|:----------------:|
| ![Dashboard](listing/screenshot_1_1366x768.png) | ![Devices](listing/screenshot_2_1366x768.png) | ![Analytics](listing/screenshot_3_1366x768.png) |

---

## 🛒 Installation & Microsoft Store

### 🥇 Option 1: Microsoft Store (Recommended)

Get verified, secure, auto-updating installations directly through the Microsoft Store:

[![Download on Microsoft Store](https://img.shields.io/badge/Microsoft_Store-Get_SwitchGate-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)](https://apps.microsoft.com/detail/9P5GQ7Z98MPV?hl=en-us&gl=IN&ocid=pdpshare)

- ✅ **Store Link:** [https://apps.microsoft.com/detail/9P5GQ7Z98MPV](https://apps.microsoft.com/detail/9P5GQ7Z98MPV?hl=en-us&gl=IN&ocid=pdpshare)
- ✅ **Publisher:** `Technical amit (education)`
- ✅ **Packaging:** Signed Windows MSIX Package
- ✅ **Automatic background updates** via Windows Store

---

### 💻 Option 2: Run from Source (Developers)

#### Prerequisites
- Windows 10 / 11 (64-bit)
- Python 3.11+
- Administrator Privileges (required for Win32 raw socket & ARP management)

#### Setup & Launch
```powershell
# 1. Clone the repository
git clone https://github.com/sharmashyama1988-eng/SwitchGate-Internet.git
cd SwitchGate-Internet

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch native desktop app
python desktop_app.py

# OR launch in local browser mode
python run.py
```

#### Build Standalone Executable (.exe)
```powershell
python build_exe.py
# Compiled binary created in: dist/SwitchGate/SwitchGate.exe
```

#### Prepare MSIX Store Package
```powershell
python prepare_msix_folder.py
# Stages files to MSIX_Source/ ready for MSIX Hero packaging
```

---

## 🏗️ Architecture & Modules

```
SwitchGate Internet/
│
├── 🖥️ desktop_app.py          # Native WebView2 EdgeChromium window + system tray
├── 🚀 run.py                   # Universal FastAPI browser runner
├── 📦 build_exe.py             # PyInstaller build pipeline
├── 📦 prepare_msix_folder.py   # MSIX Store staging & packaging tool
│
├── backend/
│   ├── config.py               # MSIX-safe path resolver + network auto-detection
│   ├── database.py             # SQLite WAL-mode persistent store
│   ├── main.py                 # FastAPI backend + Real-Time WebSocket Hub (1s TICK)
│   │
│   ├── core/
│   │   ├── activator.py        # ⚡ Parallel engine launcher (11 concurrent background threads)
│   │   ├── admin_power.py      # Silent Win32 privilege escalation
│   │   ├── scanner.py          # Multi-stage ARP sweep + NetBIOS + Windows ARP cache
│   │   ├── blocker.py          # Layer-2 ARP interceptor & kernel firewall dropper
│   │   ├── dns_sinkhole.py     # UDP 53/5353 DNS sinkhole (ad/telemetry blocker)
│   │   ├── traffic_monitor.py  # Per-device real-time bandwidth calculator
│   │   ├── scheduler.py        # Bedtime cutoff & sleep timer scheduler
│   │   ├── ghost_detector.py   # Stealth scan & unauthorized device detector
│   │   ├── app_controller.py   # Per-app Windows firewall controller
│   │   └── url_controller.py   # Real-time domain interceptor & PAC proxy
│   │
│   ├── kperf/                  # Rust-accelerated socket interceptor & ring buffer
│   └── routers/                # REST API routes (devices, network, adblock, schedules, apps)
│
├── frontend/
│   ├── index.html              # Cyber Obsidian master dashboard
│   ├── css/style.css           # Glassmorphic dark UI styling
│   └── js/                     # UI controller, WebSocket engine, 60 FPS canvas charts
│
└── msix/
    └── AppxManifest.xml        # Microsoft Store package manifest (v2.0.2.0)
```

---

## 🔒 Security & Privacy Statement

- **100% Local Execution**: No external cloud telemetry, no central analytics server, no user data collection.
- **Zero Third-Party Tracking**: Your connected devices and network logs never leave your personal computer.
- **Full Transparency**: Open-source core architecture allows full inspection and security audits.

---

## 📄 License & Attribution

Distributed under Proprietary License for **Technical amit (education)**.  
Source code is made available on GitHub for community verification, security auditing, and transparency.

© 2026 Technical amit (education). All rights reserved.

<div align="center">

**Built with ❤️ in India 🇮🇳**

[![Get it from Microsoft Store](https://img.shields.io/badge/Microsoft%20Store-SwitchGate%20Internet-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)](https://apps.microsoft.com/detail/9P5GQ7Z98MPV?hl=en-us&gl=IN&ocid=pdpshare)

</div>
