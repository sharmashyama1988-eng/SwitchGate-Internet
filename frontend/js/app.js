/**
 * SwitchGate - Master UI Controller v2.0
 * Real-Time Apps Network Control, Visited Sites Circuit Breaker & LAN Devices
 * Hardened WebSocket Synchronization & Bulletproof State Reconciliation
 */

const AppState = {
  activeView: "dashboard",
  devices: [],
  apps: [],
  websites: [],
  intruders: [],
  ghostLeaks: [],
  networkInfo: {},
  emergencyPauseActive: false,
  settings: {}
};

const CategoryIcons = {
  browser: "🌐",
  social: "💬",
  gaming: "🎮",
  media: "🎵",
  devtools: "⚡",
  system: "⚙️",
  tools: "📦"
};

// Pending mutation tracker to prevent incoming WebSocket ticks from overriding in-flight user toggles
const pendingMutations = new Map();

function setPendingMutation(key, value, ttlMs = 3000) {
  pendingMutations.set(key, { value, expiresAt: Date.now() + ttlMs });
}

function getPendingMutation(key) {
  const item = pendingMutations.get(key);
  if (!item) return undefined;
  if (Date.now() > item.expiresAt) {
    pendingMutations.delete(key);
    return undefined;
  }
  return item.value;
}

function clearPendingMutation(key) {
  pendingMutations.delete(key);
}

document.addEventListener("DOMContentLoaded", () => {
  fetchInitialState();

  // Connect live WebSocket
  window.sgSocket.connect();

  // Real-time Connection Status Indicator Listener
  window.sgSocket.on("status", (info) => {
    const headerStatusContainer = document.getElementById("headerConnectionStatus");
    if (!headerStatusContainer) return;
    const gwIp = AppState.networkInfo.gateway_ip || "192.168.1.1";

    if (info.status === "CONNECTED") {
      headerStatusContainer.innerHTML = `
        <span>Status:</span>
        <span class="text-emerald-400 font-bold flex items-center gap-1.5">
          <span class="w-2 h-2 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400 animate-pulse"></span> Live Stream (<span id="headerGatewayIp">${escapeHtml(gwIp)}</span>)
        </span>
      `;
    } else if (info.status === "FALLBACK") {
      headerStatusContainer.innerHTML = `
        <span>Status:</span>
        <span class="text-amber-400 font-bold flex items-center gap-1.5">
          <span class="w-2 h-2 rounded-full bg-amber-400 shadow-sm shadow-amber-400"></span> Fallback Polling (<span id="headerGatewayIp">${escapeHtml(gwIp)}</span>)
        </span>
      `;
    } else if (info.status === "RECONNECTING" || info.status === "CONNECTING") {
      headerStatusContainer.innerHTML = `
        <span>Status:</span>
        <span class="text-rose-400 font-bold flex items-center gap-1.5">
          <span class="w-2 h-2 rounded-full bg-rose-400 shadow-sm shadow-rose-400 animate-ping"></span> Reconnecting...
        </span>
      `;
    } else {
      headerStatusContainer.innerHTML = `
        <span>Status:</span>
        <span class="text-slate-400 font-bold flex items-center gap-1.5">
          <span class="w-2 h-2 rounded-full bg-slate-500"></span> Disconnected
        </span>
      `;
    }
  });

  window.sgSocket.on("TICK", (data) => {
    if (!data) return;

    // 1. Live Global Metrics
    if (data.metrics) {
      const downMbps = typeof data.metrics.download_mbps === "number" ? data.metrics.download_mbps : 0.0;
      const liveSpeed = `${downMbps.toFixed(1)} MB/s`;
      const sideSpeed = document.getElementById("sidebarLiveSpeed");
      if (sideSpeed) sideSpeed.innerText = liveSpeed;
      const dashDown = document.getElementById("dashDownSpeed");
      if (dashDown) dashDown.innerText = liveSpeed;

      if (window.bandwidthChart) {
        window.bandwidthChart.updateTelemetry({
          ...data.metrics,
          kperf: data.kperf
        });
      }
    }

    // 2. Real Running Windows Apps
    if (Array.isArray(data.apps)) {
      AppState.apps = data.apps.map(incomingApp => {
        const pendingBlocked = getPendingMutation(`app_${incomingApp.name.toLowerCase()}`);
        if (pendingBlocked !== undefined) {
          return { ...incomingApp, is_blocked: pendingBlocked };
        }
        return incomingApp;
      });
      const sideApps = document.getElementById("sidebarAppCount");
      if (sideApps) sideApps.innerText = AppState.apps.length;
      const dashApps = document.getElementById("dashActiveApps");
      if (dashApps) dashApps.innerText = AppState.apps.length;
      if (AppState.activeView === "apps") {
        renderAppsList();
      }
    }

    // 3. Real Live Visited Websites
    if (Array.isArray(data.websites)) {
      AppState.websites = data.websites.map(incomingSite => {
        const pendingBlocked = getPendingMutation(`site_${incomingSite.domain.toLowerCase()}`);
        if (pendingBlocked !== undefined) {
          return { ...incomingSite, is_blocked: pendingBlocked };
        }
        return incomingSite;
      });
      const sideSites = document.getElementById("sidebarSiteCount");
      if (sideSites) sideSites.innerText = AppState.websites.length;
      const dashSites = document.getElementById("dashTrackedSites");
      if (dashSites) dashSites.innerText = AppState.websites.length;
      if (AppState.activeView === "websites") {
        renderWebsitesList();
      }
    }

    // 4. LAN Devices
    if (Array.isArray(data.devices)) {
      AppState.devices = data.devices.map(incomingDev => {
        const mac = (incomingDev.mac || "").toLowerCase();
        const pendingLeft = getPendingMutation(`dev_left_${mac}`);
        const pendingRight = getPendingMutation(`dev_right_${mac}`);
        const devCopy = { ...incomingDev };
        if (pendingLeft !== undefined) {
          devCopy.left_switch_on = pendingLeft;
          devCopy.is_blocked = !pendingLeft;
        }
        if (pendingRight !== undefined) {
          devCopy.right_switch_on = pendingRight;
        }
        return devCopy;
      });
      updateDeviceCounts();
      if (AppState.activeView === "devices") {
        renderDeviceCards();
      }
    }

    // 5. Emergency Pause & Alerts
    if (data.emergency_pause !== undefined) {
      const pendingPause = getPendingMutation("emergency_pause");
      const activeState = pendingPause !== undefined ? pendingPause : data.emergency_pause;
      updateEmergencyPauseUI(activeState);
    }

    if (Array.isArray(data.intruders)) {
      AppState.intruders = data.intruders;
      renderIntruderBanner();
    }

    if (Array.isArray(data.ghost_leaks)) {
      AppState.ghostLeaks = data.ghost_leaks;
      const sideGhost = document.getElementById("sidebarGhostCount");
      if (sideGhost) sideGhost.innerText = data.ghost_leaks.length;
      if (AppState.activeView === "ghosts") renderGhostLeaks();
    }

    // 6. kPerf Kernel Hypervisor Live Telemetry
    if (data.kperf) {
      const kStatus = document.getElementById("headerKperfStatus");
      if (kStatus && data.kperf.cpu_overhead) {
        kStatus.innerText = `${data.kperf.cpu_overhead} CPU`;
      }
      const kShadows = document.getElementById("headerKperfShadows");
      if (kShadows && data.kperf.total_shadows_streamed !== undefined) {
        kShadows.innerText = Number(data.kperf.total_shadows_streamed).toLocaleString();
      }
      const dShadows = document.getElementById("dashKperfShadows");
      if (dShadows && data.kperf.total_shadows_streamed !== undefined) {
        dShadows.innerText = Number(data.kperf.total_shadows_streamed).toLocaleString();
      }
      const dRst = document.getElementById("dashKperfRst");
      if (dRst && data.kperf.total_rst_injected !== undefined) {
        dRst.innerText = Number(data.kperf.total_rst_injected).toLocaleString();
      }
    }

    // 7. Next-Gen Firewall & Threat Shield Live Telemetry
    if (data.firewall) {
      updateFirewallTelemetryUI(data.firewall);
    }
  });
});

async function fetchInitialState() {
  try {
    const [netRes, devRes, appRes, siteRes, ghostRes, setRes, adRes] = await Promise.all([
      fetch("/api/network/info"),
      fetch("/api/devices"),
      fetch("/api/apps"),
      fetch("/api/websites"),
      fetch("/api/ghost-leaks"),
      fetch("/api/settings"),
      fetch("/api/adblock/stats")
    ]);

    AppState.networkInfo = await netRes.json();
    AppState.devices = await devRes.json();
    AppState.apps = await appRes.json();
    AppState.websites = await siteRes.json();
    AppState.ghostLeaks = await ghostRes.json();
    AppState.settings = await setRes.json();
    const adStats = await adRes.json();

    const gwIp = AppState.networkInfo.gateway_ip || "192.168.1.1";
    const headerGw = document.getElementById("headerGatewayIp");
    if (headerGw) headerGw.innerText = gwIp;
    const setGw = document.getElementById("settingsGateway");
    if (setGw) setGw.innerText = gwIp;
    const setLocal = document.getElementById("settingsLocalIp");
    if (setLocal) setLocal.innerText = AppState.networkInfo.local_ip || "127.0.0.1";
    const setIface = document.getElementById("settingsIface");
    if (setIface) setIface.innerText = AppState.networkInfo.interface || "Default Adapter";

    const sideApp = document.getElementById("sidebarAppCount");
    if (sideApp) sideApp.innerText = AppState.apps.length;
    const sideSite = document.getElementById("sidebarSiteCount");
    if (sideSite) sideSite.innerText = AppState.websites.length;

    populateAdvancedSettings(AppState.settings);

    updateDeviceCounts();
    renderDeviceCards();
    renderAppsList();
    renderWebsitesList();
    renderGhostLeaks();
    switchView("dashboard");
  } catch (e) {
    console.error("[SwitchGate] Fetch initial state error:", e);
  }
}

// Navigation Switcher
function switchView(viewName) {
  AppState.activeView = viewName;

  document.querySelectorAll(".nav-link").forEach(link => link.classList.remove("active"));
  const activeLink = document.getElementById(`nav-${viewName}`);
  if (activeLink) activeLink.classList.add("active");

  ["devices", "apps", "websites", "dashboard", "firewall", "ghosts", "logs", "settings"].forEach(v => {
    const el = document.getElementById(`view-${v}`);
    if (el) {
      if (v === viewName) {
        el.classList.remove("hidden");
      } else {
        el.classList.add("hidden");
      }
    }
  });

  if (viewName === "dashboard") {
    if (window.bandwidthChart) {
      setTimeout(() => window.bandwidthChart.setupResize(), 50);
    } else if (window.initBandwidthChart) {
      setTimeout(() => window.initBandwidthChart(), 50);
    }
  }
  if (viewName === "apps") renderAppsList();
  if (viewName === "websites") renderWebsitesList();
  if (viewName === "devices") renderDeviceCards();
  if (viewName === "ghosts") renderGhostLeaks();
  if (viewName === "logs") loadActivityLogs();
  if (viewName === "firewall") {
    fetchFirewallRules();
    fetchFirewallLogs();
  }
  if (viewName === "settings") {
    fetch("/api/settings").then(r => r.json()).then(s => populateAdvancedSettings(s)).catch(() => {});
  }
}

// ================= 1. APPS NETWORK CONTROL RENDERING =================
function renderAppsList() {
  const container = document.getElementById("appsGrid");
  if (!container) return;

  const query = (document.getElementById("appSearchInput")?.value || "").toLowerCase().trim();
  const filtered = AppState.apps.filter(app => {
    if (!query) return true;
    return (app.name || "").toLowerCase().includes(query) || (app.friendly_name || "").toLowerCase().includes(query);
  });

  if (filtered.length === 0) {
    container.innerHTML = `<div class="col-span-full py-12 text-center text-slate-500 font-medium">No running apps match your search.</div>`;
    return;
  }

  container.innerHTML = filtered.map(app => {
    const isBlocked = !!app.is_blocked;
    const catIcon = CategoryIcons[app.category] || "📦";
    const speedKbps = app.current_kbps || 0;
    const speedText = speedKbps > 1024 ? `${(speedKbps / 1024).toFixed(1)} MB/s` : `${Math.round(speedKbps)} KB/s`;
    const pidsList = Array.isArray(app.pids) && app.pids.length > 0 ? app.pids.slice(0, 2).join(", ") : "Enforced (Offline)";

    return `
      <div class="glass-card ${isBlocked ? 'is-blocked-card' : ''} flex flex-col justify-between">
        <!-- Top Row: Icon + Friendly Name & Exe -->
        <div>
          <div class="flex items-start justify-between gap-3 mb-2">
            <div class="flex items-center gap-3 min-w-0">
              <div class="app-icon-box flex-shrink-0">
                ${catIcon}
              </div>
              <div class="min-w-0">
                <h4 class="font-bold text-white text-sm truncate" title="${escapeHtml(app.friendly_name || app.name)}">${escapeHtml(app.friendly_name || app.name)}</h4>
                <div class="text-[11px] font-mono text-slate-400 truncate">${escapeHtml(app.name)}</div>
              </div>
            </div>

            <!-- Status Badge -->
            ${isBlocked ? `
              <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 flex-shrink-0">INTERNET OFF</span>
            ` : `
              <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/25 flex-shrink-0">ACTIVE</span>
            `}
          </div>

          <!-- Process Info Bar -->
          <div class="bg-black/30 rounded-xl p-2 border border-white/5 my-3 text-[11px] font-mono text-slate-400 flex items-center justify-between">
            <div class="truncate">
              <span class="text-slate-500">PID:</span> <span class="text-slate-200">${escapeHtml(pidsList)}</span>
              <span class="text-slate-500 ml-2">Sockets:</span> ${app.connections_count || 0}
            </div>
            <div class="text-right flex-shrink-0 ml-2">
              <span class="${isBlocked ? 'text-slate-600 line-through' : 'text-cyan-400'} font-bold">${speedText}</span>
            </div>
          </div>
        </div>

        <!-- Bottom: Instant ON / OFF Switch (Firewall Circuit Breaker) -->
        <div class="pt-2 border-t border-white/5 flex items-center justify-between">
          <span class="text-[11px] text-slate-400">Internet Connection</span>
          
          <div class="switch-pill ${isBlocked ? 'pill-off-red' : 'pill-on-cyan'}" onclick="handleAppToggle('${escapeHtml(app.name)}', '${escapeHtml(app.exe_path || '')}', ${isBlocked ? "'ON'" : "'OFF'"})">
            <span>${isBlocked ? 'OFF' : 'ON'}</span>
            <span class="pill-knob"></span>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

// Toggle App Internet Access without Killing Process
async function handleAppToggle(appName, exePath, action) {
  if (window.soundFX) {
    if (action === "ON") {
      window.soundFX.playSwitchOn();
    } else {
      window.soundFX.playSwitchOff();
    }
  }

  const targetBlocked = action === "OFF";
  const appKey = appName.toLowerCase();
  
  // Register pending mutation to lock UI state
  setPendingMutation(`app_${appKey}`, targetBlocked, 3500);

  // Optimistic UI update
  const app = AppState.apps.find(a => a.name.toLowerCase() === appKey);
  if (app) {
    app.is_blocked = targetBlocked;
    renderAppsList();
  }

  try {
    const res = await fetch(`/api/apps/${encodeURIComponent(appName)}/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: action, exe_path: exePath })
    });
    const data = await res.json();
    clearPendingMutation(`app_${appKey}`);
    showToast(action === "OFF" ? "App Internet Cut Off" : "App Internet Restored", data.message, action === "OFF" ? "danger" : "success");
  } catch (e) {
    clearPendingMutation(`app_${appKey}`);
    showToast("Error", "Failed to update app firewall rule", "warning");
  }
}

// ================= 2. LIVE WEBSITES & URLS RENDERING =================
function renderWebsitesList() {
  const container = document.getElementById("websitesGrid");
  if (!container) return;

  if (AppState.websites.length === 0) {
    container.innerHTML = `<div class="col-span-full py-12 text-center text-slate-500 font-medium">No live websites recorded yet. Open any browser to see live streams!</div>`;
    return;
  }

  container.innerHTML = AppState.websites.map(site => {
    const isBlocked = !!site.is_blocked;

    return `
      <div class="glass-card ${isBlocked ? 'is-blocked-card' : ''} flex flex-col justify-between">
        <div>
          <div class="flex items-start justify-between gap-3 mb-2">
            <div class="flex items-center gap-3 min-w-0">
              <div class="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20 flex items-center justify-center font-bold text-sm flex-shrink-0">
                🌐
              </div>
              <div class="min-w-0">
                <h4 class="font-bold text-white text-sm truncate">${escapeHtml(site.friendly_name || site.domain)}</h4>
                <div class="text-[11px] font-mono text-cyan-400 truncate">${escapeHtml(site.domain)}</div>
              </div>
            </div>

            <!-- Status Pill -->
            ${isBlocked ? `
              <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 flex-shrink-0">BLOCKED</span>
            ` : `
              <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/25 flex-shrink-0">ALLOWED</span>
            `}
          </div>

          <div class="bg-black/30 rounded-xl p-2 border border-white/5 my-3 text-[11px] font-mono text-slate-400 flex items-center justify-between">
            <div class="truncate">
              <span class="text-slate-500">Category:</span> <span class="text-slate-200">${escapeHtml(site.category || 'Web')}</span>
            </div>
            <div class="text-right flex-shrink-0 ml-2">
              <span class="text-purple-400 font-bold">${site.hits || 0} hits</span>
            </div>
          </div>
        </div>

        <div class="pt-2 border-t border-white/5 flex items-center justify-between">
          <span class="text-[11px] text-slate-400">Domain Access</span>
          
          <div class="switch-pill ${isBlocked ? 'pill-off-red' : 'pill-on-cyan'}" onclick="handleWebsiteToggle('${escapeHtml(site.domain)}', ${isBlocked ? "'ON'" : "'OFF'"})">
            <span>${isBlocked ? 'OFF' : 'ON'}</span>
            <span class="pill-knob"></span>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

async function handleWebsiteToggle(domain, action) {
  if (window.soundFX) {
    if (action === "ON") {
      window.soundFX.playSwitchOn();
    } else {
      window.soundFX.playSwitchOff();
    }
  }

  const targetBlocked = action === "OFF";
  const domainKey = domain.toLowerCase();
  
  // Register pending mutation
  setPendingMutation(`site_${domainKey}`, targetBlocked, 3500);

  const site = AppState.websites.find(s => s.domain.toLowerCase() === domainKey);
  if (site) {
    site.is_blocked = targetBlocked;
    renderWebsitesList();
  }

  try {
    const res = await fetch(`/api/websites/${encodeURIComponent(domain)}/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: action })
    });
    const data = await res.json();
    clearPendingMutation(`site_${domainKey}`);
    showToast(action === "OFF" ? "Website Blocked" : "Website Restored", data.message, action === "OFF" ? "danger" : "success");
  } catch (e) {
    clearPendingMutation(`site_${domainKey}`);
    showToast("Error", "Failed to update domain rule", "warning");
  }
}

async function addCustomBlockedSite() {
  const input = document.getElementById("siteCustomInput");
  if (!input) return;
  const domain = input.value.trim();
  if (!domain) return;

  await handleWebsiteToggle(domain, "OFF");
  input.value = "";
  fetchInitialState();
}

// ================= 3. LAN DEVICES RENDERING =================
function updateDeviceCounts() {
  const total = AppState.devices.length;
  const paused = AppState.devices.filter(d => !d.left_switch_on || d.is_blocked).length;
  const active = Math.max(0, total - paused);

  const sideDev = document.getElementById("sidebarDeviceCount");
  if (sideDev) sideDev.innerText = total;
  const cntAct = document.getElementById("countActive");
  if (cntAct) cntAct.innerText = active;
  const cntPsd = document.getElementById("countPaused");
  if (cntPsd) cntPsd.innerText = paused;
  const dashCount = document.getElementById("dashTotalCount");
  if (dashCount) dashCount.innerText = total;
}

function renderDeviceCards() {
  const container = document.getElementById("deviceCardsContainer");
  if (!container) return;

  if (AppState.devices.length === 0) {
    container.innerHTML = `
      <div class="col-span-full py-16 text-center text-slate-500">
        <svg class="w-12 h-12 mx-auto mb-3 opacity-40" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>
        <p class="text-base font-medium">Scanning for live LAN devices on your Wi-Fi...</p>
        <button onclick="triggerScan()" class="mt-3 px-4 py-2 rounded-xl bg-cyan-500 text-black text-xs font-bold">Rescan Network</button>
      </div>
    `;
    return;
  }

  container.innerHTML = AppState.devices.map(dev => createDeviceCardHTML(dev)).join("");
}

function createDeviceCardHTML(dev) {
  const leftOn = dev.left_switch_on !== undefined ? dev.left_switch_on : !dev.is_blocked;
  const rightOn = dev.right_switch_on !== undefined ? dev.right_switch_on : !dev.is_blocked;
  const isTurbo = !!dev.is_turbo;

  let statusHTML = "";
  if (!leftOn) {
    statusHTML = `
      <div class="flex items-center gap-2 text-xs font-semibold text-rose-500">
        <span class="w-2 h-2 rounded-full bg-rose-500"></span>
        <span>${escapeHtml(dev.status_label || 'Internet Access Paused')}</span>
      </div>
    `;
  } else {
    statusHTML = `
      <div class="flex items-center gap-2 text-xs font-semibold text-emerald-400">
        <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
        <span class="text-slate-300">${escapeHtml(dev.status_label || (isTurbo ? 'Connected | High Priority' : 'Connected | Active'))}</span>
      </div>
    `;
  }

  const leftSwitchClass = leftOn ? "pill-on-cyan" : "pill-off";
  let rightSwitchClass = "pill-off-red";
  if (rightOn) {
    rightSwitchClass = isTurbo ? "pill-on-turbo" : "pill-on-cyan";
  }

  return `
    <div class="device-card">
      <div class="flex items-start gap-4">
        <div class="device-icon-box flex-shrink-0">
          📡
        </div>
        <div class="min-w-0 flex-1">
          <h4 class="font-bold text-white text-base tracking-wide truncate">${escapeHtml(dev.custom_name || dev.ip)}</h4>
          <p class="text-xs text-slate-400 font-medium mt-0.5 truncate">${escapeHtml(dev.vendor || 'Generic Device')} • ${escapeHtml(dev.ip)}</p>
        </div>
      </div>

      <div class="my-4">
        ${statusHTML}
      </div>

      <div class="flex items-center gap-3 pt-2">
        <div class="switch-pill ${leftSwitchClass}" onclick="handleSwitchClick('${escapeHtml(dev.mac)}', 'left', ${!leftOn})">
          <span>${leftOn ? 'ON' : 'OFF'}</span>
          <span class="pill-knob"></span>
        </div>

        <div class="switch-pill ${rightSwitchClass}" onclick="handleSwitchClick('${escapeHtml(dev.mac)}', 'right', ${!rightOn})">
          <span>${rightOn ? 'ON' : 'OFF'}</span>
          <span class="pill-knob"></span>
        </div>
      </div>
    </div>
  `;
}

async function handleSwitchClick(mac, switchSide, targetState) {
  if (window.soundFX) {
    if (targetState) {
      window.soundFX.playSwitchOn();
    } else {
      window.soundFX.playSwitchOff();
    }
  }

  const macKey = mac.toLowerCase();
  setPendingMutation(`dev_${switchSide}_${macKey}`, targetState, 3500);

  const dev = AppState.devices.find(d => d.mac.toLowerCase() === macKey);
  if (dev) {
    if (switchSide === 'left') {
      dev.left_switch_on = targetState;
      dev.is_blocked = !targetState;
    } else {
      dev.right_switch_on = targetState;
    }
    renderDeviceCards();
    updateDeviceCounts();
  }

  try {
    const payload = switchSide === 'left' ? { left_on: targetState } : { right_on: targetState };
    await fetch(`/api/devices/${mac}/switch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    clearPendingMutation(`dev_${switchSide}_${macKey}`);
    showToast("Switch Updated", `${dev ? dev.custom_name : mac} ${switchSide.toUpperCase()} switch set to ${targetState ? 'ON' : 'OFF'}`, "success");
  } catch (e) {
    clearPendingMutation(`dev_${switchSide}_${macKey}`);
    showToast("Error", "Failed to update switch state", "warning");
  }
}

// Emergency Pause
async function toggleEmergencyPause() {
  const newActive = !AppState.emergencyPauseActive;
  if (window.soundFX) {
    if (newActive) {
      window.soundFX.playPanicAlert();
    } else {
      window.soundFX.playSwitchOn();
    }
  }

  setPendingMutation("emergency_pause", newActive, 3500);
  updateEmergencyPauseUI(newActive);

  try {
    const res = await fetch("/api/devices/emergency-pause", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ active: newActive })
    });
    const data = await res.json();
    clearPendingMutation("emergency_pause");
    showToast(newActive ? "DINNER TIME FREEZE" : "INTERNET RESTORED", data.message, newActive ? "danger" : "success");
  } catch (e) {
    clearPendingMutation("emergency_pause");
    showToast("Error", "Failed to toggle emergency pause", "warning");
  }
}

function updateEmergencyPauseUI(active) {
  AppState.emergencyPauseActive = active;
  const btn = document.getElementById("btnEmergencyPause");
  const dot = document.getElementById("emergencyDot");
  const label = document.getElementById("emergencyPauseLabel");
  if (!btn || !dot || !label) return;

  if (active) {
    btn.className = "flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-bold bg-rose-600 text-white shadow-lg shadow-rose-600/30 border border-rose-500 animate-pulse";
    dot.className = "w-2 h-2 rounded-full bg-white";
    label.innerText = "🚨 HOME WI-FI FROZEN";
  } else {
    btn.className = "flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-bold bg-white/5 hover:bg-rose-500/20 text-slate-300 hover:text-rose-400 border border-white/10 hover:border-rose-500/40 transition";
    dot.className = "w-2 h-2 rounded-full bg-slate-400";
    label.innerText = "PAUSE HOME WI-FI";
  }
}

// Intruder Alert Banner
function renderIntruderBanner() {
  const container = document.getElementById("intruderAlertContainer");
  if (!container) return;

  if (AppState.intruders.length === 0) {
    container.classList.add("hidden");
    container.innerHTML = "";
    return;
  }

  const intruder = AppState.intruders[0];
  container.classList.remove("hidden");
  container.innerHTML = `
    <div class="intruder-banner p-4 flex items-center justify-between gap-4">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-rose-500/20 text-rose-400 flex items-center justify-center font-bold text-xl animate-bounce">
          🚨
        </div>
        <div>
          <h4 class="font-extrabold text-white text-sm tracking-wide flex items-center gap-2">
            <span>INTRUDER ALERT: UNKNOWN DEVICE DETECTED</span>
            <span class="text-[10px] bg-rose-500 text-white px-2 py-0.5 rounded font-mono font-bold">UNAUTHORIZED</span>
          </h4>
          <p class="text-xs text-slate-300 font-mono mt-0.5">
            ${escapeHtml(intruder.vendor || 'Unknown')} • IP: <span class="text-rose-300 font-bold">${escapeHtml(intruder.ip)}</span> • MAC: ${escapeHtml(intruder.mac)}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button onclick="banIntruder('${escapeHtml(intruder.mac)}')" class="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-lg shadow-rose-600/40 transition">
          ⛔ BAN & BLACKLIST
        </button>
      </div>
    </div>
  `;
}

async function banIntruder(mac) {
  try {
    await fetch(`/api/intruders/${mac}/ban`, { method: "POST" });
    showToast("Intruder Banned", `Device ${mac} permanently cut off from Wi-Fi`, "danger");
    AppState.intruders = AppState.intruders.filter(i => i.mac !== mac);
    renderIntruderBanner();
  } catch (e) {
    showToast("Error", "Failed to ban intruder", "warning");
  }
}

// Ghost Leaks View
function renderGhostLeaks() {
  const list = document.getElementById("ghostLeaksList");
  if (!list) return;

  if (AppState.ghostLeaks.length === 0) {
    list.innerHTML = `<div class="col-span-full py-12 text-center text-slate-500 font-medium">🛡️ No active ghost data leaks detected. Zero background data drain.</div>`;
    return;
  }

  list.innerHTML = AppState.ghostLeaks.map(leak => `
    <div class="glass-card flex items-center justify-between">
      <div class="min-w-0 flex-1 mr-4">
        <div class="flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
          <h4 class="font-bold text-white text-sm truncate">${escapeHtml(leak.company)}</h4>
        </div>
        <div class="font-mono text-xs text-slate-400 mt-1 truncate">${escapeHtml(leak.domain)}</div>
        <div class="text-[11px] text-slate-500 mt-1">Draining <span class="text-amber-400 font-bold font-mono">${leak.leak_kbps || 0} KB/s</span> in background</div>
      </div>
      <button onclick="killGhostLeak(${leak.id})" class="px-3.5 py-2 rounded-xl bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs font-bold transition flex-shrink-0">
        ⚡ KILL LEAK
      </button>
    </div>
  `).join("");
}

async function killGhostLeak(leakId) {
  try {
    await fetch(`/api/ghost-leaks/${leakId}/kill`, { method: "POST" });
    showToast("Leak Vaporized", "Domain blocked. Stealth data transfer halted.", "success");
    AppState.ghostLeaks = AppState.ghostLeaks.filter(l => l.id !== leakId);
    renderGhostLeaks();
  } catch (e) {
    showToast("Error", "Failed to terminate ghost leak", "warning");
  }
}

// Activity Logs
async function loadActivityLogs() {
  const container = document.getElementById("logsContainer");
  if (!container) return;
  try {
    const res = await fetch("/api/network/logs?limit=35");
    const logs = await res.json();
    container.innerHTML = logs.map(l => `
      <div class="flex items-center gap-3 py-1.5 border-b border-white/5">
        <span class="text-slate-500 text-[11px] flex-shrink-0">${escapeHtml(l.timestamp)}</span>
        <span class="px-1.5 py-0.5 rounded text-[10px] font-bold flex-shrink-0 ${l.event_type.includes('BLOCK') ? 'bg-rose-500/20 text-rose-400' : 'bg-cyan-500/20 text-cyan-400'}">${escapeHtml(l.event_type)}</span>
        <span class="text-slate-300 flex-1 truncate">${escapeHtml(l.details)}</span>
      </div>
    `).join("");
  } catch (e) {}
}

// ================= 6. ADVANCED SETTINGS HANDLERS =================
function populateAdvancedSettings(s) {
  if (!s) return;
  
  // 1. Core Network
  const adapterEl = document.getElementById("settingAdapterBinding");
  if (adapterEl && s.adapter_binding) adapterEl.value = s.adapter_binding;
  const failsafeEl = document.getElementById("settingFailsafeMode");
  if (failsafeEl && s.failsafe_mode) failsafeEl.value = s.failsafe_mode;
  const dpiEl = document.getElementById("settingDpiDepth");
  if (dpiEl && s.dpi_depth) dpiEl.value = s.dpi_depth;
  const autoProfEl = document.getElementById("settingAutoProfile");
  if (autoProfEl) autoProfEl.checked = !!s.auto_profile_switching;

  // 2. Advanced Traffic & Apps
  const procEl = document.getElementById("settingProcessBlocking");
  if (procEl) procEl.checked = !!s.process_blocking_enabled;
  const protoEl = document.getElementById("settingProtocolHardening");
  if (protoEl) protoEl.checked = !!s.protocol_hardening;
  const stealthEl = document.getElementById("settingStealthMode");
  if (stealthEl) stealthEl.checked = !!s.stealth_mode;
  const throttleEl = document.getElementById("settingBandwidthThrottling");
  if (throttleEl) throttleEl.checked = !!s.bandwidth_throttling;

  // 3. Security, AV & Content
  const adbAggEl = document.getElementById("settingAdblockAggression");
  if (adbAggEl && s.adblock_aggression) adbAggEl.value = s.adblock_aggression;
  const payloadEl = document.getElementById("settingPayloadHash");
  if (payloadEl) payloadEl.checked = !!s.realtime_payload_hashing;
  const safeEl = document.getElementById("settingSafeSearch");
  if (safeEl) safeEl.checked = !!s.dns_safesearch;
  const intelEl = document.getElementById("settingThreatIntel");
  if (intelEl) intelEl.checked = !!s.threat_intel_auto_update;

  // 4. Connection Security
  const secDnsEl = document.getElementById("settingSecureDns");
  if (secDnsEl && s.secure_dns_doh) secDnsEl.value = s.secure_dns_doh;
  const ipsecEl = document.getElementById("settingEnforceIpsec");
  if (ipsecEl) ipsecEl.checked = !!s.enforce_ipsec;
  const vpnEl = document.getElementById("settingVpnPassthrough");
  if (vpnEl) vpnEl.checked = !!s.vpn_passthrough;
  const quarEl = document.getElementById("settingQuarantine");
  if (quarEl) quarEl.checked = !!s.auto_quarantine;

  // 5. Auditing & Self-Protection
  const auditEl = document.getElementById("settingAuditLevel");
  if (auditEl && s.audit_logging_level) auditEl.value = s.audit_logging_level;
  const logRetEl = document.getElementById("settingLogRetention");
  if (logRetEl && s.log_retention_days) logRetEl.value = String(s.log_retention_days);
  const antiTamperEl = document.getElementById("settingAntiTamper");
  if (antiTamperEl) antiTamperEl.checked = !!s.anti_tamper_protection;
  const attackEl = document.getElementById("settingAttackAlerting");
  if (attackEl) attackEl.checked = !!s.live_attack_alerting;
  const startupEl = document.getElementById("settingStartup");
  if (startupEl) startupEl.checked = !!s.run_on_startup;
  const trayEl = document.getElementById("settingTray");
  if (trayEl) trayEl.checked = !!s.minimize_to_tray;
}

async function saveAdvancedSetting(key, val) {
  try {
    const payload = {};
    payload[key] = val;
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      showToast("Setting Updated", `${key.replace(/_/g, ' ')} synchronized`, "success");
    }
  } catch (e) {
    showToast("Error", `Failed to save ${key}`, "warning");
  }
}

async function saveAllAdvancedSettings() {
  const payload = {
    // 1. Core Network
    adapter_binding: document.getElementById("settingAdapterBinding")?.value,
    failsafe_mode: document.getElementById("settingFailsafeMode")?.value,
    dpi_depth: document.getElementById("settingDpiDepth")?.value,
    auto_profile_switching: document.getElementById("settingAutoProfile")?.checked,

    // 2. Traffic & Apps
    process_blocking_enabled: document.getElementById("settingProcessBlocking")?.checked,
    protocol_hardening: document.getElementById("settingProtocolHardening")?.checked,
    stealth_mode: document.getElementById("settingStealthMode")?.checked,
    bandwidth_throttling: document.getElementById("settingBandwidthThrottling")?.checked,

    // 3. Security & Smart Filtering
    adblock_aggression: document.getElementById("settingAdblockAggression")?.value,
    realtime_payload_hashing: document.getElementById("settingPayloadHash")?.checked,
    dns_safesearch: document.getElementById("settingSafeSearch")?.checked,
    threat_intel_auto_update: document.getElementById("settingThreatIntel")?.checked,

    // 4. Connection Security
    secure_dns_doh: document.getElementById("settingSecureDns")?.value,
    enforce_ipsec: document.getElementById("settingEnforceIpsec")?.checked,
    vpn_passthrough: document.getElementById("settingVpnPassthrough")?.checked,
    auto_quarantine: document.getElementById("settingQuarantine")?.checked,

    // 5. Auditing & Self-Protection
    audit_logging_level: document.getElementById("settingAuditLevel")?.value,
    log_retention_days: parseInt(document.getElementById("settingLogRetention")?.value || "14"),
    anti_tamper_protection: document.getElementById("settingAntiTamper")?.checked,
    live_attack_alerting: document.getElementById("settingAttackAlerting")?.checked,
    run_on_startup: document.getElementById("settingStartup")?.checked,
    minimize_to_tray: document.getElementById("settingTray")?.checked
  };

  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      showToast("Enterprise Settings Saved", "All 5 categories updated & synced with kernel engines", "success");
    }
  } catch (e) {
    showToast("Error", "Failed to save advanced settings", "danger");
  }
}

async function saveSystemSettings() {
  await saveAllAdvancedSettings();
}

function openScheduleModal() {
  const select = document.getElementById("schedDeviceSelect");
  if (select) {
    select.innerHTML = AppState.devices.map(d => `<option value="${escapeHtml(d.mac)}">${escapeHtml(d.custom_name || d.ip)} (${escapeHtml(d.vendor || 'Device')})</option>`).join("");
  }
  openModal("scheduleModal");
}

async function submitNewSchedule() {
  const mac = document.getElementById("schedDeviceSelect")?.value;
  const start = document.getElementById("schedStartTime")?.value;
  const end = document.getElementById("schedEndTime")?.value;
  const name = document.getElementById("schedRuleName")?.value;

  if (!mac || !start || !end) return;

  try {
    await fetch("/api/schedules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mac: mac, start_time: start, end_time: end, name: name || "Bedtime Rule" })
    });
    closeModal("scheduleModal");
    showToast("Schedule Created", `Bedtime cutoff active for ${start} - ${end}`, "success");
  } catch (e) {
    showToast("Error", "Failed to create schedule", "warning");
  }
}

async function triggerScan() {
  showToast("Scanning Network", "Discovering connected LAN Wi-Fi devices...", "info");
  try {
    await fetch("/api/network/scan", { method: "POST" });
    setTimeout(() => fetchInitialState(), 2000);
  } catch (e) {
    showToast("Scan Error", "Could not start network scan", "warning");
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ================= NEXT-GEN FIREWALL & THREAT SHIELD =================
function updateFirewallTelemetryUI(fw) {
  if (!fw) return;
  
  const inspected = document.getElementById("fwPacketsInspected");
  if (inspected && fw.total_packets_inspected !== undefined) {
    inspected.innerText = Number(fw.total_packets_inspected).toLocaleString();
  }

  const dropped = document.getElementById("fwPacketsDropped");
  if (dropped && fw.total_packets_dropped !== undefined) {
    dropped.innerText = Number(fw.total_packets_dropped).toLocaleString();
  }

  const malware = document.getElementById("fwMalwareDetected");
  if (malware && fw.total_malware_detected !== undefined) {
    malware.innerText = Number(fw.total_malware_detected).toLocaleString();
  }

  const threatsCount = (fw.total_packets_dropped || 0) + (fw.total_malware_detected || 0);
  const sideThreats = document.getElementById("sidebarFirewallThreats");
  if (sideThreats) {
    sideThreats.innerText = threatsCount;
  }

  const netshState = document.getElementById("fwNetshState");
  if (netshState && fw.windows_firewall_status) {
    netshState.innerText = fw.windows_firewall_status.state || "ACTIVE";
  }

  const fwBadge = document.getElementById("fwStatusBadge");
  if (fwBadge && fw.enabled !== undefined) {
    fwBadge.innerText = fw.enabled ? "ACTIVE (ON)" : "DISABLED (OFF)";
    fwBadge.className = fw.enabled
      ? "text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono font-bold hover:bg-emerald-500/20 transition cursor-pointer"
      : "text-xs px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 font-mono font-bold hover:bg-rose-500/20 transition cursor-pointer";
  }

  if (fw.current_profile) {
    updateProfileButtonsUI(fw.current_profile);
  }
}

async function toggleFirewallMaster() {
  try {
    const res = await fetch("/api/firewall/toggle", { method: "POST" });
    const data = await res.json();
    const isEnabled = data.enabled;
    const fwBadge = document.getElementById("fwStatusBadge");
    if (fwBadge) {
      fwBadge.innerText = isEnabled ? "ACTIVE (ON)" : "DISABLED (OFF)";
      fwBadge.className = isEnabled
        ? "text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono font-bold hover:bg-emerald-500/20 transition cursor-pointer"
        : "text-xs px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 font-mono font-bold hover:bg-rose-500/20 transition cursor-pointer";
    }
    showToast(isEnabled ? "Firewall Active" : "Firewall Disabled", data.message, isEnabled ? "success" : "warning");
  } catch (e) {
    showToast("Error", "Failed to toggle firewall state", "danger");
  }
}

function updateProfileButtonsUI(activeProfile) {
  ["Public", "Private", "Domain"].forEach(p => {
    const btn = document.getElementById(`fwProf${p}`);
    if (btn) {
      if (p === activeProfile) {
        btn.className = "px-3 py-1 rounded-lg transition font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30";
      } else {
        btn.className = "px-3 py-1 rounded-lg transition font-bold text-slate-400 hover:text-white";
      }
    }
  });
}

async function setFirewallProfile(profile) {
  try {
    const res = await fetch("/api/firewall/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ profile: profile })
    });
    const data = await res.json();
    updateProfileButtonsUI(profile);
    showToast("Profile Switched", `Firewall active profile set to ${profile}`, "success");
    fetchFirewallRules();
  } catch (e) {
    showToast("Error", "Failed to switch firewall profile", "warning");
  }
}

async function fetchFirewallRules() {
  try {
    const res = await fetch("/api/firewall/rules");
    const data = await res.json();
    renderFirewallRules(data.custom_rules || []);
    if (data.current_profile) {
      updateProfileButtonsUI(data.current_profile);
    }
  } catch (e) {}
}

function renderFirewallRules(rules) {
  const container = document.getElementById("fwRulesList");
  if (!container) return;

  if (!rules || rules.length === 0) {
    container.innerHTML = `<div class="py-6 text-center text-slate-500">No custom ACL rules. Standard profile defaults active.</div>`;
    return;
  }

  container.innerHTML = rules.map(r => `
    <div class="p-3 bg-black/40 border border-white/5 rounded-xl flex items-center justify-between gap-3">
      <div class="min-w-0 flex-1">
        <div class="flex items-center gap-2">
          <span class="w-1.5 h-1.5 rounded-full ${r.enabled ? 'bg-emerald-400' : 'bg-slate-600'}"></span>
          <span class="font-bold text-white text-xs truncate">${escapeHtml(r.name)}</span>
          <span class="text-[10px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-400 font-bold">${escapeHtml(r.action || 'DROP')}</span>
        </div>
        <div class="text-[11px] text-slate-400 mt-0.5 font-mono truncate">
          ${escapeHtml(r.type)} ${escapeHtml(r.target)} • ${escapeHtml(r.direction)}
        </div>
      </div>
      <div class="flex items-center gap-2 flex-shrink-0">
        <button onclick="toggleFirewallRule('${escapeHtml(r.id)}')" class="px-2.5 py-1 rounded-lg text-[11px] font-bold ${r.enabled ? 'bg-white/10 text-white' : 'bg-slate-800 text-slate-500'}">
          ${r.enabled ? 'Enabled' : 'Disabled'}
        </button>
        <button onclick="deleteFirewallRule('${escapeHtml(r.id)}')" class="p-1 rounded-lg text-slate-500 hover:text-rose-400">
          🗑️
        </button>
      </div>
    </div>
  `).join("");
}

async function addCustomFirewallRule() {
  const name = document.getElementById("fwRuleName")?.value.trim();
  const ruleType = document.getElementById("fwRuleType")?.value;
  const direction = document.getElementById("fwRuleDirection")?.value;
  const target = document.getElementById("fwRuleTarget")?.value.trim();

  if (!name || !target) {
    showToast("Invalid Input", "Please provide a rule name and target IP/Port", "warning");
    return;
  }

  try {
    const res = await fetch("/api/firewall/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, type: ruleType, direction, target, action: "DROP" })
    });
    if (res.ok) {
      showToast("Rule Created", `Blocked ${ruleType} ${target}`, "success");
      document.getElementById("fwRuleName").value = "";
      document.getElementById("fwRuleTarget").value = "";
      fetchFirewallRules();
    }
  } catch (e) {
    showToast("Error", "Failed to add firewall rule", "danger");
  }
}

async function toggleFirewallRule(ruleId) {
  try {
    await fetch(`/api/firewall/rules/${ruleId}/toggle`, { method: "POST" });
    fetchFirewallRules();
  } catch (e) {}
}

async function deleteFirewallRule(ruleId) {
  try {
    await fetch(`/api/firewall/rules/${ruleId}`, { method: "DELETE" });
    showToast("Rule Deleted", "Firewall ACL removed", "info");
    fetchFirewallRules();
  } catch (e) {}
}

async function fetchFirewallLogs() {
  const container = document.getElementById("fwAuditLogList");
  if (!container) return;
  try {
    const res = await fetch("/api/firewall/logs?limit=30");
    const logs = await res.json();
    if (!logs || logs.length === 0) {
      container.innerHTML = `<div class="py-4 text-center text-slate-500">Live sniffer monitoring. No malicious drops in current session.</div>`;
      return;
    }
    container.innerHTML = logs.map(l => `
      <div class="flex items-center gap-3 py-1 border-b border-white/5">
        <span class="text-slate-500 text-[10px] flex-shrink-0">${escapeHtml(l.timestamp)}</span>
        <span class="px-1.5 py-0.2 rounded text-[10px] font-bold ${l.action === 'DROP' ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400'}">${escapeHtml(l.action)}</span>
        <span class="text-slate-300 flex-1 truncate">${escapeHtml(l.reason)} • <span class="text-slate-400">${escapeHtml(l.src_ip)} &rarr; ${escapeHtml(l.dst_ip)}:${escapeHtml(l.dst_port || l.port || '')}</span></span>
      </div>
    `).join("");
  } catch (e) {}
}
