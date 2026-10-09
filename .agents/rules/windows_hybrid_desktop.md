---
description: Critical engineering invariants for Windows Hybrid Desktop (FastAPI + WebView2) and Network Controllers.
always_on: true
---

# Windows Hybrid Desktop & Network Engineering Invariants

## 1. Windows Batch Script Encoding (`cmd.exe`)
- All `.bat` and `.cmd` launcher files must use 100% strict ASCII or start with `chcp 65001 >nul`.
- Never include UTF-8 multi-byte glyphs (emojis, smart quotes, em-dashes) in unquoted lines or comments; Windows `cmd.exe` parses these bytes into corrupted sub-commands (e.g. `'ocal'`, `'e'`, `'d'`).
- Always offer a modern PowerShell (`.ps1`) launcher with automatic self-elevation (`Start-Process -Verb RunAs`).

## 2. Process & Network Socket Enumeration Resilience
- Never assume `psutil.net_connections()` succeeds; on standard Windows user tokens it raises `psutil.AccessDenied`.
- Wrap network socket inspection in granular try-catch blocks and combine with `psutil.process_iter(['pid', 'name', 'exe'])`.
- Filter Windows kernel/system background noise (`System`, `csrss.exe`, `lsass.exe`, `dwm.exe`, etc.) while guaranteeing all user applications (browsers, media players, developer tools, gaming clients) are always enumerated and controllable.

## 3. Web SDK & Cloud Identity Synchronization (Firebase / OAuth)
- Never defer SDK initialization behind an asynchronous `fetch()` if user interface elements (buttons, modals) can invoke SDK methods immediately.
- Always provide synchronous fallback initialization (`ensureInitialized()`) with default configurations.
- In desktop webview or localhost environments, intercept unauthorized domain or network failures and provide automatic local session simulation (`simulateDemoSignIn`) so guest administrators are never blocked by cloud misconfigurations.

## 4. Multi-Layer Domain & Website Interception
- Real-time website controllers must not rely on a single interception vector.
- Combine:
  1. Pre-seeded popular web service matrix for immediate 1-click toggles.
  2. Kernel socket table inspection (`kperf_engine` / `GetExtendedTcpTable`).
  3. Windows DNS Client cache harvesting (`Get-DnsClientCache`).
- Ensure all sorting keys use safe type coercion (`int(hits or 0)`) to prevent runtime `TypeError` exceptions.
