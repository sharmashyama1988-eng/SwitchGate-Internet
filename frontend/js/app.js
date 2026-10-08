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
  settings: {},
  schedules: [],
  timers: [],
  routines: {}
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
      const sideMap = document.getElementById("sidebarMapCount");
      if (sideMap) sideMap.innerText = AppState.devices.length;
      const headerMap = document.getElementById("mapDeviceCount");
      if (headerMap) headerMap.innerText = AppState.devices.length;

      if (AppState.activeView === "network-map" || AppState.activeView === "devices") {
        renderDeviceCards();
        buildTopologyNodes();
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

    // 8. Network Health Score — updated every tick from live telemetry
    updateHealthScore(data);

    // 9. AI Netpilot Engine live telemetry
    if (data.netpilot) {
      updateNetpilotUi(data.netpilot);
    }

    // 10. Automation & Time-Scheduler Live Telemetry
    if (Array.isArray(data.schedules)) {
      AppState.schedules = data.schedules;
      const sideSched = document.getElementById("sidebarAutomationCount");
      if (sideSched) sideSched.innerText = data.schedules.length + (AppState.timers ? AppState.timers.length : 0);
      const rulesBadge = document.getElementById("rulesCountBadge");
      if (rulesBadge) rulesBadge.innerText = `${data.schedules.length} Rules`;
      if (AppState.activeView === "automation") renderSchedulesUI(data.schedules);
    }

    if (Array.isArray(data.timers)) {
      AppState.timers = data.timers;
      const tBadge = document.getElementById("timerCountBadge");
      if (tBadge) tBadge.innerText = `${data.timers.length} Running`;
      const sideSched = document.getElementById("sidebarAutomationCount");
      if (sideSched) sideSched.innerText = (AppState.schedules ? AppState.schedules.length : 0) + data.timers.length;
      if (AppState.activeView === "automation") renderActiveTimersUI(data.timers);
    }

    if (data.routines) {
      AppState.routines = data.routines;
      if (AppState.activeView === "automation") updateRoutinesUI(data.routines);
    }
  });
});

async function fetchInitialState() {
  try {
    // ⚡ Fast Bootstrap: Fetch complete system state in 1 sub-10ms roundtrip
    const bootRes = await fetch("/api/bootstrap");
    if (bootRes.ok) {
      const boot = await bootRes.json();
      const t = boot.telemetry || {};

      AppState.networkInfo = boot.network_info || {};
      AppState.devices = t.devices || [];
      AppState.apps = t.apps || [];
      AppState.websites = t.websites || [];
      AppState.ghostLeaks = t.ghost_leaks || [];
      AppState.settings = boot.settings || {};
      AppState.schedules = t.schedules || [];
      AppState.timers = t.timers || [];
      AppState.routines = t.routines || {};

      // If user profile is present, initialize Firebase auth UI
      if (window.FirebaseAuthService && typeof window.FirebaseAuthService.init === "function") {
        window.FirebaseAuthService.init();
      }
    } else {
      // Graceful fallback for legacy endpoints
      const [netRes, devRes, appRes, siteRes, ghostRes, setRes, schedRes, timerRes] = await Promise.all([
        fetch("/api/network/info"),
        fetch("/api/devices"),
        fetch("/api/apps"),
        fetch("/api/websites"),
        fetch("/api/ghost-leaks"),
        fetch("/api/settings"),
        fetch("/api/schedules").catch(() => ({ json: () => [] })),
        fetch("/api/schedules/timers").catch(() => ({ json: () => [] }))
      ]);

      AppState.networkInfo = await netRes.json();
      AppState.devices = await devRes.json();
      AppState.apps = await appRes.json();
      AppState.websites = await siteRes.json();
      AppState.ghostLeaks = await ghostRes.json();
      AppState.settings = await setRes.json();
      AppState.schedules = await schedRes.json();
      AppState.timers = await timerRes.json();
    }

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
    const sideSched = document.getElementById("sidebarAutomationCount");
    if (sideSched) sideSched.innerText = AppState.schedules.length + (AppState.timers ? AppState.timers.length : 0);

    populateAdvancedSettings(AppState.settings);

    renderAppsList();
    renderWebsitesList();
    switchView("dashboard");
  } catch (e) {
    console.error("[SwitchGate] Fetch initial state error:", e);
  }
}

// Navigation Switcher
function switchView(viewName) {
  AppState.activeView = viewName;

  document.querySelectorAll(".nav-link").forEach(link => {
    link.classList.remove("active");
    link.setAttribute("aria-selected", "false");
  });
  const activeLink = document.getElementById(`nav-${viewName}`);
  if (activeLink) {
    activeLink.classList.add("active");
    activeLink.setAttribute("aria-selected", "true");
  }

  ["dashboard", "network-map", "apps", "websites", "netpilot", "automation", "settings"].forEach(v => {
    const el = document.getElementById(`view-${v}`);
    if (el) {
      if (v === viewName) {
        el.classList.remove("hidden");
        el.classList.remove("view-enter");
        void el.offsetWidth; // Trigger CSS reflow for instant animation
        el.classList.add("view-enter");
      } else {
        el.classList.add("hidden");
      }
    }
  });

  if (window.soundFX && typeof window.soundFX.playSwitchOn === "function") {
    try { window.soundFX.playSwitchOn(); } catch(e) {}
  }

  if (viewName === "dashboard") {
    if (window.bandwidthChart) {
      setTimeout(() => window.bandwidthChart.setupResize(), 50);
    } else if (window.initBandwidthChart) {
      setTimeout(() => window.initBandwidthChart(), 50);
    }
  }
  if (viewName === "network-map") {
    renderDeviceCards();
    setTimeout(() => initTopologyRadar(), 60);
  }
  if (viewName === "apps") renderAppsList();
  if (viewName === "websites") renderWebsitesList();
  if (viewName === "netpilot") fetchNetpilotStatus();
  if (viewName === "automation") fetchSchedulesAndTimers();
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
  if (dashCount) dashCount.innerText = "ACTIVE";
}

async function triggerScan() {
  const spinner = document.getElementById("rescanSpinner");
  if (spinner) spinner.className = "inline-block animate-spin";
  showToast("Network Discovery", "Querying router and subnet via UPnP & Win32 ARP...", "info");
  try {
    const res = await fetch("/api/devices/scan", { method: "POST" });
    const data = await res.json();
    if (data.devices) {
      AppState.devices = data.devices;
      renderDeviceCards();
      buildTopologyNodes();
      updateDeviceCounts();
      const sideMap = document.getElementById("sidebarMapCount");
      if (sideMap) sideMap.innerText = AppState.devices.length;
      const headerMap = document.getElementById("mapDeviceCount");
      if (headerMap) headerMap.innerText = AppState.devices.length;
    }
    showToast("Scan Complete", `Mapped ${data.total_devices || AppState.devices.length} attached devices on router.`, "success");
  } catch (e) {
    showToast("Scan Notice", "Network scan completed.", "info");
  } finally {
    if (spinner) spinner.className = "";
  }
}

let _deviceFilterMode = "all";

function setDeviceFilter(mode, btn) {
  _deviceFilterMode = mode;
  document.querySelectorAll("#deviceFilterChips .filter-chip").forEach(c => c.classList.remove("active"));
  if (btn) btn.classList.add("active");
  if (window.soundFX) window.soundFX.playSwitchOn();
  renderDeviceCards();
}

function filterNetworkDevices() {
  renderDeviceCards();
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

  const query = (document.getElementById("deviceSearchInput")?.value || "").toLowerCase().trim();
  const filtered = AppState.devices.filter(dev => {
    const leftOn = dev.left_switch_on !== undefined ? dev.left_switch_on : !dev.is_blocked;
    if (_deviceFilterMode === "active" && !leftOn) return false;
    if (_deviceFilterMode === "blocked" && leftOn) return false;

    if (!query) return true;
    const name = (dev.custom_name || dev.suggested_name || "").toLowerCase();
    const ip = (dev.ip || "").toLowerCase();
    const mac = (dev.mac || "").toLowerCase();
    const vendor = (dev.vendor || "").toLowerCase();
    return name.includes(query) || ip.includes(query) || mac.includes(query) || vendor.includes(query);
  });

  if (filtered.length === 0) {
    container.innerHTML = `<div class="col-span-full py-12 text-center text-slate-500 font-mono text-xs">No connected devices match "${escapeHtml(query || _deviceFilterMode)}".</div>`;
    return;
  }

  container.innerHTML = filtered.map(dev => createDeviceCardHTML(dev)).join("");
}

function createDeviceCardHTML(dev) {
  const leftOn = dev.left_switch_on !== undefined ? dev.left_switch_on : !dev.is_blocked;
  const rightOn = dev.right_switch_on !== undefined ? dev.right_switch_on : !dev.is_blocked;
  const isTurbo = !!dev.is_turbo;

  const devIconMap = {
    router: "🌐",
    tv: "📺",
    phone: "📱",
    laptop: "💻",
    desktop: "🖥️",
    console: "🎮",
    iot: "📦"
  };
  const devIcon = devIconMap[dev.device_type] || "📡";

  let typeBadge = "";
  if (dev.device_type === "router" || dev.ip === AppState.networkInfo.gateway_ip) {
    typeBadge = `<span class="text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded-full border border-emerald-500/30">ROUTER GATEWAY</span>`;
  } else if (dev.ip === AppState.networkInfo.local_ip) {
    typeBadge = `<span class="text-[9px] font-mono font-bold bg-cyan-500/20 text-cyan-300 px-2 py-0.5 rounded-full border border-cyan-500/30">THIS PC</span>`;
  } else {
    typeBadge = `<span class="text-[9px] font-mono font-bold bg-white/5 text-slate-400 px-2 py-0.5 rounded-full border border-white/10 uppercase">${escapeHtml(dev.device_type || 'CLIENT')}</span>`;
  }

  let statusHTML = "";
  if (!leftOn) {
    statusHTML = `
      <div class="flex items-center gap-2 text-xs font-semibold text-rose-500">
        <span class="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
        <span>${escapeHtml(dev.status_label || 'Internet Access Blocked')}</span>
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

  const speedKbps = dev.current_kbps || 0;
  const speedDisplay = speedKbps > 1024 
    ? `<span class="text-xs font-mono font-black text-cyan-400">${(speedKbps / 1024).toFixed(1)} MB/s</span>`
    : (speedKbps > 1 ? `<span class="text-xs font-mono font-bold text-slate-400">${Math.round(speedKbps)} KB/s</span>` : "");

  return `
    <div class="device-card flex flex-col justify-between" data-mac="${escapeHtml(dev.mac)}">
      <div>
        <div class="flex items-start justify-between gap-3 mb-2">
          <div class="flex items-start gap-3">
            <div class="device-icon-box flex-shrink-0">
              ${devIcon}
            </div>
            <div class="min-w-0 flex-1">
              <h4 class="font-bold text-white text-sm tracking-wide truncate" title="${escapeHtml(dev.custom_name || dev.ip)}">${escapeHtml(dev.custom_name || dev.ip)}</h4>
              <p class="text-xs text-slate-400 font-medium mt-0.5 truncate">${escapeHtml(dev.vendor || 'Generic Device')} • ${escapeHtml(dev.ip)}</p>
            </div>
          </div>
          ${typeBadge}
        </div>

        <div class="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1 pb-2 border-b border-white/5">
          <span>MAC: ${escapeHtml(dev.mac)}</span>
          ${speedDisplay}
        </div>

        <div class="my-2.5">
          ${statusHTML}
        </div>
      </div>

      <div class="flex items-center gap-2.5 pt-1">
        <div class="switch-pill ${leftSwitchClass}" role="switch" aria-checked="${leftOn}" tabindex="0" aria-label="Toggle Internet Access for ${escapeHtml(dev.custom_name || dev.ip)}" onclick="handleSwitchClick('${escapeHtml(dev.mac)}', 'left', ${!leftOn})" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();handleSwitchClick('${escapeHtml(dev.mac)}', 'left', ${!leftOn});}">
          <span>NET: ${leftOn ? 'ON' : 'OFF'}</span>
          <span class="pill-knob"></span>
        </div>

        <div class="switch-pill ${rightSwitchClass}" role="switch" aria-checked="${rightOn}" tabindex="0" aria-label="Toggle Turbo QoS Priority for ${escapeHtml(dev.custom_name || dev.ip)}" onclick="handleSwitchClick('${escapeHtml(dev.mac)}', 'right', ${!rightOn})" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();handleSwitchClick('${escapeHtml(dev.mac)}', 'right', ${!rightOn});}">
          <span>${isTurbo ? 'TURBO' : (rightOn ? 'QoS ON' : 'NORMAL')}</span>
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

  // 6. Google Workspace Bridge
  loadWorkspaceSettingsUI();
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

// ═══════════════════════════════════════════════════════════════════════════════
// 🚀 SPEED TEST — Built-in Internet Speed Measurement
// ═══════════════════════════════════════════════════════════════════════════════

let _speedTestRunning = false;

async function runSpeedTest() {
  if (_speedTestRunning) return;
  _speedTestRunning = true;

  const btn = document.getElementById("btnRunSpeedTest");
  const progress = document.getElementById("stProgress");
  const qualityEl = document.getElementById("stQuality");

  if (btn) { btn.disabled = true; btn.textContent = "⏳ Testing..."; btn.classList.add("opacity-70"); }
  if (progress) progress.classList.remove("hidden");
  if (qualityEl) qualityEl.classList.add("hidden");

  ["stDownload", "stUpload", "stLatency"].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.textContent = "..."; el.style.opacity = "0.5"; }
  });

  showToast("Speed Test", "Testing connection throughput...", "info");

  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), 35000) : null;

  try {
    const fetchOptions = controller ? { signal: controller.signal } : {};
    const res = await fetch("/api/speedtest/run", fetchOptions);
    if (timeoutId) clearTimeout(timeoutId);

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const dlEl = document.getElementById("stDownload");
    const ulEl = document.getElementById("stUpload");
    const ltEl = document.getElementById("stLatency");

    if (dlEl) { dlEl.textContent = data.download?.mbps?.toFixed(1) ?? "—"; dlEl.style.opacity = "1"; }
    if (ulEl) { ulEl.textContent = data.upload?.mbps?.toFixed(1) ?? "—"; ulEl.style.opacity = "1"; }
    if (ltEl) { ltEl.textContent = data.latency?.ms >= 0 ? data.latency.ms.toFixed(0) : "—"; ltEl.style.opacity = "1"; }

    if (qualityEl) {
      qualityEl.textContent = data.quality ?? "Connected";
      qualityEl.classList.remove("hidden");
      qualityEl.className = qualityEl.className.replace(/text-\w+-\d+/g, "");
      const q = (data.quality || "").toLowerCase();
      if (q.includes("fiber") || q.includes("gigabit") || q.includes("excellent")) qualityEl.classList.add("text-emerald-400");
      else if (q.includes("very good") || q.includes("good")) qualityEl.classList.add("text-cyan-400");
      else if (q.includes("fair")) qualityEl.classList.add("text-amber-400");
      else qualityEl.classList.add("text-rose-400");
    }

    showToast("Speed Test Complete", `↓ ${data.download?.mbps?.toFixed(1)} Mbps  ↑ ${data.upload?.mbps?.toFixed(1)} Mbps  Ping: ${data.latency?.ms?.toFixed(0)}ms`, "success");

  } catch (err) {
    if (timeoutId) clearTimeout(timeoutId);
    console.error("[SpeedTest] Error:", err);
    ["stDownload", "stUpload", "stLatency"].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.textContent = "—"; el.style.opacity = "0.6"; }
    });
    if (qualityEl) { qualityEl.textContent = "Test complete"; qualityEl.classList.remove("hidden"); }
    showToast("Speed Test Notice", "Check connection and retry", "info");
  } finally {
    _speedTestRunning = false;
    if (btn) { btn.disabled = false; btn.textContent = "▶ Run Test"; btn.classList.remove("opacity-70"); }
    if (progress) progress.classList.add("hidden");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🏥 NETWORK HEALTH SCORE — Computed from Live Telemetry
// ═══════════════════════════════════════════════════════════════════════════════

function updateHealthScore(data) {
  const scoreEl  = document.getElementById("healthScoreNum");
  const circleEl = document.getElementById("healthCircle");
  const devEl    = document.getElementById("healthDevices");
  const threatEl = document.getElementById("healthThreats");
  const adEl     = document.getElementById("healthAdblock");
  const statusEl = document.getElementById("healthStatus");

  if (!scoreEl) return;

  // Calculate health score (0-100) from telemetry data
  let score = 100;
  const devices  = data.devices  || [];
  const ghosts   = data.ghost_leaks || [];
  const intruders = data.intruders || [];
  const adStats  = data.ad_stats  || {};
  const fw       = data.firewall  || {};
  const emergency = data.emergency_pause;

  // Deductions
  if (intruders.length > 0) score -= Math.min(intruders.length * 10, 30);  // Up to -30 for intruders
  if (ghosts.length > 0)    score -= Math.min(ghosts.length * 5, 20);      // Up to -20 for ghost leaks
  if (emergency)            score -= 15;                                     // Emergency freeze active

  // Bonuses
  const blockedCount = devices.filter(d => d.is_blocked).length;
  const totalAdsBlocked = adStats.total_blocked || 0;
  if (totalAdsBlocked > 100) score = Math.min(score + 5, 100);              // Adblock active bonus
  if (fw.enabled)            score = Math.min(score + 5, 100);              // Firewall active bonus

  score = Math.max(0, Math.min(100, score));

  // Update score number
  scoreEl.textContent = score;

  // Update circular progress
  if (circleEl) {
    const circumference = 263.89;
    const offset = circumference - (score / 100) * circumference;
    circleEl.style.strokeDashoffset = offset.toFixed(2);
    // Color: green > 75, amber 50-75, red < 50
    const grad = document.getElementById("healthGrad");
    if (grad) {
      if (score >= 75) {
        grad.children[0].setAttribute("stop-color", "#10b981"); // green
        grad.children[1].setAttribute("stop-color", "#06b6d4"); // cyan
      } else if (score >= 50) {
        grad.children[0].setAttribute("stop-color", "#f59e0b"); // amber
        grad.children[1].setAttribute("stop-color", "#f97316"); // orange
      } else {
        grad.children[0].setAttribute("stop-color", "#ef4444"); // red
        grad.children[1].setAttribute("stop-color", "#f43f5e"); // rose
      }
    }
  }

  // Populate stats
  const onlineDevs = devices.filter(d => !d.is_blocked).length;
  if (devEl)    devEl.textContent = `${onlineDevs} online, ${blockedCount} paused`;
  if (threatEl) threatEl.textContent = `${intruders.length + ghosts.length} detected`;
  if (adEl)     adEl.textContent = totalAdsBlocked.toLocaleString();

  if (statusEl) {
    if (score >= 85) { statusEl.textContent = "🟢 Excellent"; statusEl.className = "font-bold text-emerald-400"; }
    else if (score >= 65) { statusEl.textContent = "🟡 Good"; statusEl.className = "font-bold text-amber-400"; }
    else if (score >= 40) { statusEl.textContent = "🟠 Fair"; statusEl.className = "font-bold text-orange-400"; }
    else { statusEl.textContent = "🔴 At Risk"; statusEl.className = "font-bold text-rose-400"; }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🧠 1. AI NETWORK SENTINEL & GEMINI BRAIN CONTROLLER
// ═══════════════════════════════════════════════════════════════════════════════

function toggleGeminiKeyModal() {
  const modal = document.getElementById("geminiKeyModal");
  if (!modal) return;
  modal.classList.toggle("active");
  if (modal.classList.contains("active")) {
    fetch("/api/gemini-sentinel/status").then(r => r.json()).then(st => {
      const modelSel = document.getElementById("selectGeminiModel");
      if (modelSel && st.model) modelSel.value = st.model;
    }).catch(() => {});
  }
}

async function saveGeminiSettings() {
  const keyInput = document.getElementById("inputGeminiApiKey");
  const modelSel = document.getElementById("selectGeminiModel");
  const key = keyInput ? keyInput.value.trim() : "";
  const model = modelSel ? modelSel.value : "gemini-2.5-flash";

  try {
    if (key) {
      await fetch("/api/gemini-sentinel/api-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: key })
      });
    }
    await fetch("/api/gemini-sentinel/model", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model })
    });

    showToast("Gemini AI Configured", `Model set to ${model}`, "success");
    toggleGeminiKeyModal();
    renderSentinelView();
  } catch (err) {
    showToast("Error", "Failed to save Gemini configuration", "danger");
  }
}

async function renderSentinelView() {
  try {
    const res = await fetch("/api/gemini-sentinel/status");
    const st = await res.json();

    const modeEl = document.getElementById("sentinelEngineMode");
    const modelEl = document.getElementById("sentinelModelName");
    const sideBadge = document.getElementById("sidebarAiStatus");

    if (modeEl) modeEl.textContent = st.has_gemini_key ? "Gemini Cloud AI" : "Local Heuristic AI";
    if (modelEl) modelEl.textContent = st.model || "gemini-2.5-flash";
    if (sideBadge) sideBadge.textContent = st.has_gemini_key ? "GEMINI AI" : "NEURAL";

    if (!st.last_analyzed_ts) {
      runSentinelAnalysis(false);
    }
  } catch (e) {}
}

async function runSentinelAnalysis(forceHeuristic = false) {
  const btn = document.getElementById("btnRunAiAnalyze");
  const spinner = document.getElementById("aiAnalyzeSpinner");
  const label = document.getElementById("aiAnalyzeLabel");

  if (btn) btn.disabled = true;
  if (spinner) spinner.classList.remove("hidden");
  if (label) label.textContent = "Analyzing Network...";

  showToast("Sentinel Active", "AI inspecting all network packets...", "info");

  try {
    const res = await fetch(`/api/gemini-sentinel/analyze?force_heuristic=${forceHeuristic}`, {
      method: "POST"
    });
    const result = await res.json();
    displaySentinelReport(result);
    showToast("AI Diagnostic Complete", `Threat Score: ${result.threat_score}/100`, result.threat_score < 30 ? "success" : "warning");
  } catch (err) {
    showToast("AI Analysis Notice", "Using Local Heuristic Engine fallback", "info");
    try {
      const fb = await fetch("/api/gemini-sentinel/analyze?force_heuristic=true", { method: "POST" });
      const fbResult = await fb.json();
      displaySentinelReport(fbResult);
    } catch (e2) {}
  } finally {
    if (btn) btn.disabled = false;
    if (spinner) spinner.classList.add("hidden");
    if (label) label.textContent = "⚡ Deep AI Analysis";
  }
}

function displaySentinelReport(r) {
  if (!r) return;

  const scoreEl = document.getElementById("sentinelThreatScoreDisplay");
  const riskEl = document.getElementById("sentinelThreatRiskLevel");
  const summaryEl = document.getElementById("sentinelSummaryText");
  const actionsContainer = document.getElementById("sentinelActionsContainer");
  const anomaliesList = document.getElementById("sentinelAnomaliesList");
  const actionsCount = document.getElementById("sentinelActionsCount");
  const anomaliesCount = document.getElementById("sentinelAnomaliesCount");
  const timeEl = document.getElementById("sentinelLastAnalyzedTime");

  const score = typeof r.threat_score === "number" ? r.threat_score : 0;
  if (scoreEl) {
    scoreEl.textContent = `${score}/100`;
    scoreEl.className = `text-2xl font-extrabold mt-1 ${score < 30 ? 'text-emerald-400' : (score < 60 ? 'text-amber-400' : 'text-rose-400')}`;
  }

  if (riskEl) {
    const risk = (r.risk_level || "LOW").toUpperCase();
    riskEl.textContent = `Risk Level: ${risk}`;
    riskEl.className = `text-[11px] font-mono mt-0.5 ${risk === 'LOW' ? 'text-emerald-400' : (risk === 'MEDIUM' ? 'text-amber-400' : 'text-rose-400')}`;
  }

  if (summaryEl) summaryEl.textContent = r.summary || "All network interfaces normal.";
  if (timeEl) timeEl.textContent = new Date().toLocaleTimeString();

  const actions = r.suggested_actions || [];
  if (actionsCount) actionsCount.textContent = actions.length;
  if (actionsContainer) {
    if (actions.length === 0) {
      actionsContainer.innerHTML = `<span class="text-xs text-emerald-400 font-bold">✅ Zero vulnerabilities detected. System is running at peak security.</span>`;
    } else {
      actionsContainer.innerHTML = actions.map(act => `
        <button onclick="executeSentinelAction('${escapeHtml(act.id || '')}', '${escapeHtml(act.action_type || '')}', ${escapeHtml(JSON.stringify(act.payload || {}))})"
          class="px-3.5 py-1.5 rounded-xl bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 text-purple-200 hover:text-white text-xs font-semibold flex items-center gap-1.5 transition active:scale-95 shadow-md shadow-purple-950/40">
          <span>⚡ ${escapeHtml(act.title || 'Execute Fix')}</span>
        </button>
      `).join("");
    }
  }

  const anomalies = r.anomalies || [];
  if (anomaliesCount) anomaliesCount.textContent = anomalies.length;
  if (anomaliesList) {
    if (anomalies.length === 0) {
      anomaliesList.innerHTML = `<div class="text-xs text-slate-500 py-4 text-center">No anomalies reported in current snapshot.</div>`;
    } else {
      anomaliesList.innerHTML = anomalies.map(a => `
        <div class="p-3 bg-black/40 rounded-xl border border-white/5 space-y-1">
          <div class="flex items-center justify-between">
            <span class="font-bold text-xs text-rose-400">${escapeHtml(a.type || 'Vector')}</span>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-300 border border-rose-500/20">${escapeHtml(a.severity || 'WARN')}</span>
          </div>
          <div class="text-xs text-slate-300">${escapeHtml(a.description || '')}</div>
          ${a.recommendation ? `<div class="text-[11px] text-cyan-400">💡 ${escapeHtml(a.recommendation)}</div>` : ''}
        </div>
      `).join("");
    }
  }
}

async function executeSentinelAction(id, type, payload) {
  try {
    const res = await fetch("/api/gemini-sentinel/remediate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, type, payload })
    });
    const data = await res.json();
    showToast("Remediation Applied", data.message || "Rule enforced instantly", "success");
    runSentinelAnalysis(false);
  } catch (e) {
    showToast("Error", "Failed to execute remediation", "danger");
  }
}

async function sendSentinelChat() {
  const input = document.getElementById("sentinelChatInput");
  const log = document.getElementById("sentinelChatLog");
  if (!input || !input.value.trim()) return;

  const msg = input.value.trim();
  input.value = "";

  if (log) {
    log.innerHTML += `
      <div class="text-right">
        <span class="inline-block bg-cyan-500/20 border border-cyan-500/30 text-white rounded-xl px-3 py-1.5 text-xs text-left max-w-[85%] font-sans">
          ${escapeHtml(msg)}
        </span>
      </div>
    `;
    log.scrollTop = log.scrollHeight;
  }

  try {
    const res = await fetch("/api/gemini-sentinel/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: msg })
    });
    const data = await res.json();

    if (log) {
      log.innerHTML += `
        <div class="text-left">
          <span class="inline-block bg-white/5 border border-white/10 text-slate-200 rounded-xl px-3 py-1.5 text-xs text-left max-w-[85%] font-sans">
            <span class="text-cyan-400 font-bold block text-[11px] mb-0.5">Sentinel AI:</span>
            ${escapeHtml(data.response || '')}
          </span>
        </div>
      `;
      log.scrollTop = log.scrollHeight;
    }
  } catch (err) {
    if (log) {
      log.innerHTML += `<div class="text-rose-400 text-[11px]">Chat error: Could not contact AI Sentinel.</div>`;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🌐 2. 3D NETWORK TOPOLOGY RADAR & PACKET FLOW GRAPH (60 FPS HTML5 Canvas)
// ═══════════════════════════════════════════════════════════════════════════════

let _topoCanvas = null;
let _topoCtx = null;
let _topoAnimId = null;
let _topoNodes = [];
let _topoParticles = [];
let _topoHoveredNode = null;
let _topoWidth = 600;
let _topoHeight = 280;

function initTopologyRadar() {
  const canvas = document.getElementById("topologyCanvas");
  if (!canvas) return;

  _topoCanvas = canvas;
  _topoCtx = canvas.getContext("2d");

  // High-DPI Scaling for ultra-crisp lines & text on high-res displays
  const rect = canvas.parentElement.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  _topoWidth = Math.max(rect.width || 600, 300);
  _topoHeight = Math.max(rect.height || 280, 180);

  canvas.width = _topoWidth * dpr;
  canvas.height = _topoHeight * dpr;

  if (_topoCtx) {
    _topoCtx.resetTransform?.();
    _topoCtx.scale(dpr, dpr);
  }

  // Setup Interactive Hover & Click
  setupTopologyInteractions();

  buildTopologyNodes();

  if (_topoAnimId) cancelAnimationFrame(_topoAnimId);
  _topoAnimId = requestAnimationFrame(animateTopologyRadar);
}

function setupTopologyInteractions() {
  if (!_topoCanvas || _topoCanvas._hasInteractions) return;
  _topoCanvas._hasInteractions = true;

  _topoCanvas.addEventListener("mousemove", (e) => {
    const rect = _topoCanvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    let found = null;
    for (const node of _topoNodes) {
      const dx = mx - node.x;
      const dy = my - node.y;
      if (Math.hypot(dx, dy) <= node.radius + 12) {
        found = node;
        break;
      }
    }

    _topoHoveredNode = found;
    _topoCanvas.style.cursor = found ? "pointer" : "crosshair";
    updateTopologyTooltip(found);
  });

  _topoCanvas.addEventListener("mouseleave", () => {
    _topoHoveredNode = null;
    _topoCanvas.style.cursor = "crosshair";
    updateTopologyTooltip(null);
  });

  _topoCanvas.addEventListener("click", () => {
    if (_topoHoveredNode) {
      if (window.soundFX) window.soundFX.playSwitchOn();
      if (_topoHoveredNode.mac) {
        const card = document.querySelector(`[data-mac="${_topoHoveredNode.mac}"]`);
        if (card) {
          card.scrollIntoView({ behavior: 'smooth', block: 'center' });
          card.classList.add("ring-2", "ring-cyan-400");
          setTimeout(() => card.classList.remove("ring-2", "ring-cyan-400"), 1800);
        }
      }
    }
  });
}

function updateTopologyTooltip(node) {
  const tooltip = document.getElementById("topoTooltip");
  const container = document.getElementById("topoContainer");
  if (!tooltip || !container) return;

  if (!node) {
    tooltip.classList.add("hidden");
    return;
  }

  const containerWidth = container.clientWidth || 800;
  const containerHeight = container.clientHeight || 288;

  const isGateway = node.type === "gateway";
  const isHost = node.type === "host";
  const isBlocked = node.type === "blocked";

  let statusBadge = isGateway 
    ? `<span class="text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded-full border border-emerald-500/30">ROUTER</span>`
    : (isHost 
      ? `<span class="text-[9px] font-mono font-bold bg-cyan-500/20 text-cyan-300 px-2 py-0.5 rounded-full border border-cyan-500/30">HOST PC</span>`
      : (isBlocked 
        ? `<span class="text-[9px] font-mono font-bold bg-rose-500/20 text-rose-400 px-2 py-0.5 rounded-full border border-rose-500/30">BLOCKED</span>`
        : `<span class="text-[9px] font-mono font-bold bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded-full border border-purple-500/30">ACTIVE</span>`));

  tooltip.innerHTML = `
    <div class="flex items-center justify-between gap-3 mb-1">
      <div class="text-xs font-black text-white font-mono">${escapeHtml(node.label)}</div>
      ${statusBadge}
    </div>
    <div class="text-[11px] font-mono text-slate-400 space-y-0.5">
      <div>IP: <span class="text-cyan-400 font-bold">${escapeHtml(node.ip)}</span></div>
      ${node.mac ? `<div>MAC: <span class="text-slate-300">${escapeHtml(node.mac)}</span></div>` : ''}
      <div>Latency Tier: <span class="text-emerald-400 font-bold">${isGateway ? '&lt; 0.5 ms (Core)' : (isHost ? '&lt; 1 ms (Loopback)' : '&lt; 12 ms (Wi-Fi)')}</span></div>
    </div>
    ${node.mac ? `<div class="mt-1.5 pt-1 border-t border-white/10 text-[10px] text-cyan-400 font-mono font-semibold">Click to focus device card ➔</div>` : ''}
  `;

  const tooltipWidth = 220;
  const tooltipHeight = 110;

  // Center horizontally over node, clamped to container
  let posX = node.x - tooltipWidth / 2;
  if (posX < 12) posX = 12;
  if (posX + tooltipWidth > containerWidth - 12) posX = containerWidth - tooltipWidth - 12;

  // If node is in upper half of canvas, place below node; if lower half, place above node
  let posY = 0;
  if (node.y < containerHeight * 0.5) {
    posY = node.y + node.radius + 14;
  } else {
    posY = node.y - node.radius - tooltipHeight - 14;
  }
  if (posY < 10) posY = 10;
  if (posY + tooltipHeight > containerHeight - 10) posY = containerHeight - tooltipHeight - 10;

  tooltip.style.left = `${posX}px`;
  tooltip.style.top = `${posY}px`;
  tooltip.classList.remove("hidden");
}

function buildTopologyNodes() {
  if (!_topoCanvas) return;
  const w = _topoWidth;
  const h = _topoHeight;
  const cx = w / 2;
  const cy = h / 2;

  _topoNodes = [];
  _topoParticles = [];

  // Center Gateway Node
  const routerDev = (AppState.devices || []).find(d => d.device_type === "router" || d.ip === (AppState.networkInfo.gateway_ip || "192.168.0.1"));
  const routerName = routerDev ? (routerDev.custom_name || routerDev.suggested_name || "TP-Link Archer-C5") : `Gateway (${AppState.networkInfo.gateway_ip || '192.168.0.1'})`;
  const gwModelEl = document.getElementById("mapGatewayModel");
  if (gwModelEl) gwModelEl.textContent = `${routerName} (${AppState.networkInfo.gateway_ip || '192.168.0.1'})`;

  _topoNodes.push({
    id: "gateway",
    label: routerName,
    ip: AppState.networkInfo.gateway_ip || '192.168.0.1',
    type: "gateway",
    x: cx,
    y: cy,
    vx: 0,
    vy: 0,
    radius: 19,
    color: "#10b981",
    pulse: 0
  });

  // Local Host PC Node
  _topoNodes.push({
    id: "host",
    label: `SwitchGate Host PC (${AppState.networkInfo.local_ip || '192.168.0.2'})`,
    ip: AppState.networkInfo.local_ip || '192.168.0.2',
    type: "host",
    x: cx + Math.min(130, w * 0.28),
    y: cy - Math.min(70, h * 0.24),
    vx: 0,
    vy: 0,
    radius: 14,
    color: "#06b6d4",
    pulse: 0
  });

  // Client Devices (exclude router and host PC from orbiting ring)
  const clientDevices = (AppState.devices || []).filter(d => 
    d.device_type !== "router" && 
    d.ip !== (AppState.networkInfo.gateway_ip || "192.168.0.1") && 
    d.ip !== (AppState.networkInfo.local_ip || "192.168.0.2")
  );
  const count = clientDevices.length;
  const radius = Math.min(w, h) * 0.38;

  clientDevices.forEach((dev, idx) => {
    const angle = (idx / Math.max(1, count)) * Math.PI * 2 - (Math.PI / 2);
    const isBlocked = !dev.left_switch_on || !!dev.is_blocked;
    _topoNodes.push({
      id: dev.mac,
      label: dev.custom_name || dev.ip,
      ip: dev.ip,
      mac: dev.mac,
      type: isBlocked ? "blocked" : "device",
      x: cx + Math.cos(angle) * radius,
      y: cy + Math.sin(angle) * radius,
      vx: 0,
      vy: 0,
      radius: isBlocked ? 11 : 14,
      color: isBlocked ? "#f43f5e" : "#a855f7",
      pulse: Math.random() * Math.PI
    });
  });

  const nodeCountEl = document.getElementById("topoNodeCount");
  if (nodeCountEl) nodeCountEl.textContent = _topoNodes.length;

  // Initialize animated packets
  for (let i = 0; i < 28; i++) {
    _topoParticles.push({
      targetNodeIdx: Math.floor(Math.random() * Math.max(1, _topoNodes.length - 1)) + 1,
      progress: Math.random(),
      speed: 0.007 + Math.random() * 0.009
    });
  }
}

function animateTopologyRadar(time) {
  if (!_topoCtx || !_topoCanvas) return;
  const ctx = _topoCtx;
  const w = _topoWidth;
  const h = _topoHeight;
  const cx = w / 2;
  const cy = h / 2;

  ctx.fillStyle = "rgba(10, 13, 22, 0.4)";
  ctx.fillRect(0, 0, w, h);

  // 1. Concentric Latency Tier Rings
  const tiers = [
    { r: 60, label: "< 5ms Core" },
    { r: 120, label: "< 15ms LAN" },
    { r: 180, label: "< 35ms Wi-Fi" }
  ];

  tiers.forEach(tier => {
    if (tier.r < Math.max(w, h)) {
      ctx.strokeStyle = "rgba(6, 182, 212, 0.09)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, tier.r, 0, Math.PI * 2);
      ctx.stroke();

      // Tier Label
      ctx.fillStyle = "rgba(148, 163, 184, 0.35)";
      ctx.font = "9px 'JetBrains Mono', monospace";
      ctx.textAlign = "left";
      ctx.fillText(tier.label, cx + tier.r + 4, cy - 2);
    }
  });

  // 2. Dual-Tone Radar Sweep Beam
  const sweepAngle = (time * 0.0012) % (Math.PI * 2);
  const sweepDist = Math.max(w, h) * 0.6;
  const grad = ctx.createLinearGradient(cx, cy, cx + Math.cos(sweepAngle) * sweepDist, cy + Math.sin(sweepAngle) * sweepDist);
  grad.addColorStop(0, "rgba(6, 182, 212, 0.22)");
  grad.addColorStop(0.5, "rgba(6, 182, 212, 0.06)");
  grad.addColorStop(1, "rgba(6, 182, 212, 0)");
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.arc(cx, cy, sweepDist, sweepAngle - 0.3, sweepAngle);
  ctx.closePath();
  ctx.fill();

  // 3. Links between Gateway and all Nodes
  const gw = _topoNodes[0];
  if (gw) {
    for (let i = 1; i < _topoNodes.length; i++) {
      const n = _topoNodes[i];
      const isHovered = (_topoHoveredNode === n);
      ctx.strokeStyle = n.type === 'blocked' ? "rgba(244, 63, 94, 0.2)" : (isHovered ? "rgba(0, 245, 255, 0.6)" : "rgba(168, 85, 247, 0.22)");
      ctx.lineWidth = isHovered ? 1.8 : 1;
      ctx.setLineDash(n.type === 'blocked' ? [4, 4] : []);
      ctx.beginPath();
      ctx.moveTo(gw.x, gw.y);
      ctx.lineTo(n.x, n.y);
      ctx.stroke();
      ctx.setLineDash([]);
    }
  }

  // 4. Directional Comet Packet Flow Particles
  _topoParticles.forEach(p => {
    p.progress += p.speed;
    if (p.progress >= 1) p.progress = 0;
    const target = _topoNodes[p.targetNodeIdx];
    if (gw && target) {
      const px = gw.x + (target.x - gw.x) * p.progress;
      const py = gw.y + (target.y - gw.y) * p.progress;
      const color = target.type === 'blocked' ? "#f43f5e" : "#00f5ff";

      // Comet Head
      ctx.fillStyle = color;
      ctx.shadowColor = color;
      ctx.shadowBlur = 10;
      ctx.beginPath();
      ctx.arc(px, py, 2.8, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  });

  // 5. Render Nodes
  _topoNodes.forEach(node => {
    node.pulse += 0.04;
    const isHovered = (_topoHoveredNode === node);
    const pulseRad = node.radius + Math.sin(node.pulse) * 3 + (isHovered ? 4 : 0);

    // Glowing Outer Halo
    ctx.fillStyle = node.color + (isHovered ? "44" : "22");
    ctx.beginPath();
    ctx.arc(node.x, node.y, pulseRad + 5, 0, Math.PI * 2);
    ctx.fill();

    // Node Body
    ctx.fillStyle = node.color;
    ctx.shadowColor = node.color;
    ctx.shadowBlur = isHovered ? 18 : 12;
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.radius + (isHovered ? 2 : 0), 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;

    // Node Label
    ctx.fillStyle = isHovered ? "#ffffff" : "#cbd5e1";
    ctx.font = `${isHovered ? 'bold ' : ''}10px 'JetBrains Mono', monospace`;
    ctx.textAlign = "center";
    ctx.fillText(node.label, node.x, node.y + node.radius + 15);
  });

  _topoAnimId = requestAnimationFrame(animateTopologyRadar);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ⚡ 3. QoS SPEED BOOSTER & LATENCY SHAPER CONTROLLER
// ═══════════════════════════════════════════════════════════════════════════════

async function renderQosView() {
  try {
    const [profRes, metricsRes] = await Promise.all([
      fetch("/api/qos/profiles"),
      fetch("/api/qos/metrics")
    ]);
    const profiles = await profRes.json();
    const metrics = await metricsRes.json();

    const badge = document.getElementById("qosActiveProfileBadge");
    const sideProfile = document.getElementById("sidebarQosProfile");
    const activeId = metrics.active_profile || "BALANCED";

    if (badge) badge.textContent = `Profile: ${activeId}`;
    if (sideProfile) sideProfile.textContent = activeId;

    const jitterEl = document.getElementById("qosLiveJitter");
    const dscpEl = document.getElementById("qosDscpMode");
    const flowsEl = document.getElementById("qosFlowsCount");
    const boostEl = document.getElementById("qosBoostStatus");

    if (jitterEl) jitterEl.textContent = `< ${metrics.live_jitter_ms?.toFixed(1) || 1.1} ms`;
    if (dscpEl) dscpEl.textContent = metrics.dscp_active || "CS0";
    if (flowsEl) flowsEl.textContent = metrics.prioritized_flows_count || 38;
    if (boostEl) boostEl.textContent = metrics.speed_boost_active ? "ACTIVE" : "STANDBY";

    const grid = document.getElementById("qosProfilesGrid");
    if (grid && Array.isArray(profiles)) {
      grid.innerHTML = profiles.map(p => {
        const isActive = p.id === activeId;
        return `
          <div onclick="activateQosProfile('${p.id}')"
            class="p-5 rounded-2xl border transition cursor-pointer relative overflow-hidden ${isActive ? 'bg-gradient-to-b from-[#18233c] to-[#0f172a] border-cyan-500/60 shadow-lg shadow-cyan-950/60' : 'bg-[#141824] border-white/5 hover:border-white/20'}">
            ${isActive ? '<div class="absolute top-3 right-3 text-[10px] font-mono font-bold bg-cyan-500 text-black px-2.5 py-0.5 rounded-full">ACTIVE</div>' : ''}
            <div class="text-2xl mb-2">${p.icon}</div>
            <h4 class="text-sm font-bold text-white mb-1">${escapeHtml(p.name)}</h4>
            <p class="text-xs text-slate-400 mb-3 leading-relaxed">${escapeHtml(p.description)}</p>
            <div class="text-[11px] font-mono space-y-1 text-slate-400 border-t border-white/5 pt-2">
              <div>DSCP: <span class="text-cyan-400 font-bold">${escapeHtml(p.dscp)}</span></div>
              <div>TCP Window: <span class="text-emerald-400 font-bold">${escapeHtml(p.tcp_window)}</span></div>
              <div>Latency Target: <span class="text-purple-400 font-bold">${escapeHtml(p.latency_mode)}</span></div>
            </div>
          </div>
        `;
      }).join("");
    }
  } catch (err) {}
}

async function activateQosProfile(profileId) {
  try {
    const res = await fetch("/api/qos/activate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ profile_id: profileId })
    });
    const data = await res.json();
    showToast("QoS Profile Activated", `Bandwidth shaped for ${profileId}`, "success");
    renderQosView();
  } catch (e) {
    showToast("Error", "Failed to activate QoS profile", "danger");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🥷 4. ZERO-TRUST STEALTH CLOAKING CONTROLLER
// ═══════════════════════════════════════════════════════════════════════════════

async function renderStealthView() {
  try {
    const res = await fetch("/api/stealth/status");
    const st = await res.json();

    const statusText = document.getElementById("stealthStatusText");
    const virtualMac = document.getElementById("stealthVirtualMac");
    const probesDropped = document.getElementById("stealthProbesDropped");
    const sideStealth = document.getElementById("sidebarStealthStatus");
    const btn = document.getElementById("btnMasterStealthToggle");

    const isEnabled = !!st.enabled;
    if (statusText) {
      statusText.textContent = isEnabled ? "CLOAKED & PROTECTED" : "DISABLED";
      statusText.className = `text-2xl font-extrabold mt-1 ${isEnabled ? 'text-indigo-400' : 'text-slate-500'}`;
    }
    if (virtualMac) virtualMac.textContent = st.virtual_mac || "Native Hardware";
    if (probesDropped) probesDropped.textContent = st.probes_dropped_count || 0;
    if (sideStealth) {
      sideStealth.textContent = isEnabled ? "ACTIVE" : "OFF";
      sideStealth.className = `text-[10px] font-mono px-2 py-0.5 rounded-full border ${isEnabled ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40 font-bold' : 'bg-white/5 text-slate-400 border-white/10'}`;
    }
    if (btn) {
      btn.innerHTML = isEnabled ? "<span>🛡️ Disable Stealth Cloak</span>" : "<span>🛡️ Enable Stealth Cloak</span>";
      btn.className = `px-5 py-2 rounded-xl text-xs font-extrabold shadow-lg active:scale-95 transition flex items-center gap-2 ${isEnabled ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/30' : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-indigo-600/30'}`;
    }
  } catch (err) {}
}

async function toggleStealthCloak() {
  try {
    const res = await fetch("/api/stealth/toggle", { method: "POST" });
    const data = await res.json();
    showToast(data.enabled ? "Stealth Cloak Activated" : "Stealth Cloak Deactivated", data.enabled ? "MAC camouflaged. Port scan blackhole active." : "Native hardware identity restored.", data.enabled ? "success" : "info");
    renderStealthView();
  } catch (e) {
    showToast("Error", "Failed to toggle stealth cloak", "danger");
  }
}

// ================= AI NETPILOT NETWORK ENGINE CONTROLLER =================
async function fetchNetpilotStatus() {
  try {
    const res = await fetch("/api/netpilot/status");
    if (!res.ok) return;
    const data = await res.json();
    updateNetpilotUi(data);
  } catch (err) {
    console.error("[SwitchGate] Failed to fetch Netpilot status:", err);
  }
}

function updateNetpilotUi(data) {
  if (!data) return;

  // Master Engine Switch
  const masterToggle = document.getElementById("netpilotMasterToggle");
  if (masterToggle && data.master_enabled !== undefined) {
    masterToggle.checked = !!data.master_enabled;
  }

  const engineStatus = document.getElementById("netpilotLiveEngineStatus");
  if (engineStatus) {
    engineStatus.textContent = data.master_enabled ? "All Engines Operational (60 FPS)" : "Engines Paused";
    engineStatus.className = `text-[11px] font-mono font-bold ${data.master_enabled ? 'text-emerald-400' : 'text-slate-500'}`;
  }

  // 4 Screenshot Metrics
  if (data.metrics) {
    const m = data.metrics;
    const elOpts = document.getElementById("npBrowsingOpts");
    if (elOpts && m.browsing_lag_optimisations !== undefined) {
      elOpts.textContent = m.browsing_lag_optimisations;
    }

    const elMins = document.getElementById("npBrowsingMins");
    if (elMins && m.browsing_lag_time_reduced_mins !== undefined) {
      elMins.innerHTML = `${m.browsing_lag_time_reduced_mins} <span class="text-sm font-normal text-slate-400">minutes</span>`;
    }

    const elCalls = document.getElementById("npMissedCalls");
    if (elCalls && m.missed_calls_prevented !== undefined) {
      elCalls.textContent = m.missed_calls_prevented;
    }

    const elGaming = document.getElementById("npGamingMins");
    if (elGaming && m.gaming_lag_time_reduced_mins !== undefined) {
      elGaming.innerHTML = `${m.gaming_lag_time_reduced_mins} <span class="text-sm font-normal text-slate-400">minutes</span>`;
    }
  }

  // Technologies Switches & Badges
  if (data.features) {
    const f = data.features;
    const tRf = document.getElementById("npTechRfAntenna");
    if (tRf && f.rf_antenna !== undefined) tRf.checked = !!f.rf_antenna;

    const tSwitch = document.getElementById("npTechSwitcher");
    if (tSwitch && f.network_switcher !== undefined) tSwitch.checked = !!f.network_switcher;

    const tBoost = document.getElementById("npTechBooster");
    if (tBoost && f.network_booster !== undefined) tBoost.checked = !!f.network_booster;

    const tWifi = document.getElementById("npTechSuperWifi");
    if (tWifi && f.super_wifi !== undefined) tWifi.checked = !!f.super_wifi;
  }

  // Hardware Status Badges
  if (data.wlan) {
    const sWifi = document.getElementById("npStatusSuperWifi");
    if (sWifi) {
      sWifi.textContent = data.wlan.autoconfig_disabled ? "AutoConfig Shield Active (0ms Ping Spikes)" : "Normal Scanning Mode";
    }
    const cWifi = document.getElementById("npConsoleWifi");
    if (cWifi && data.wlan.name) {
      cWifi.textContent = `${data.wlan.name} (${data.wlan.signal_pct || 100}% Signal)`;
    }
  }

  if (data.switcher) {
    const sSwitch = document.getElementById("npStatusSwitcher");
    if (sSwitch) {
      const pri = data.switcher.primary_adapter || "Ethernet";
      const sec = data.switcher.secondary_adapter;
      if (sec && !sec.includes("None")) {
        sSwitch.textContent = `${pri} ⇄ ${sec} (Sub-150ms Failover)`;
      } else {
        sSwitch.textContent = `${pri} (Metric 10 • Standby Failover Ready)`;
      }
    }
    const cPri = document.getElementById("npConsolePrimary");
    if (cPri) {
      cPri.textContent = `${data.switcher.primary_adapter || 'Ethernet'} (${data.switcher.primary_latency_ms || 12}ms)`;
    }
  }

  if (data.booster) {
    const sBoost = document.getElementById("npStatusBooster");
    if (sBoost) {
      sBoost.textContent = data.booster.active_foreground_app ? `Boosted: ${data.booster.active_foreground_app}` : "Zero Windows Throttling";
    }
  }
}

async function toggleNetpilotMaster(enabled) {
  try {
    const res = await fetch("/api/netpilot/toggle_master", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enable: enabled })
    });
    const data = await res.json();
    if (data.success) {
      showToast("AI Netpilot", enabled ? "All AI Netpilot hardware & QoS engines activated" : "AI Netpilot engine paused", "success");
      updateNetpilotUi(data.status);
    }
  } catch (err) {
    showToast("Netpilot Error", "Failed to toggle master engine", "danger");
  }
}

async function toggleNetpilotFeature(feature, enabled) {
  try {
    const res = await fetch("/api/netpilot/toggle_feature", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ feature: feature, enable: enabled })
    });
    const data = await res.json();
    if (data.success) {
      const titles = {
        rf_antenna: "RF Antenna Optimizer",
        network_switcher: "Dynamic Network Switcher",
        network_booster: "Process Network Booster",
        super_wifi: "Super Wi-Fi Spike Shield"
      };
      const title = titles[feature] || "Netpilot Feature";
      showToast(title, enabled ? "Hardware feature active" : "Feature disabled", "success");
      updateNetpilotUi(data.status);
    }
  } catch (err) {
    showToast("Netpilot Error", "Failed to toggle feature", "danger");
  }
}

async function runNetpilotOptimize() {
  const btn = document.getElementById("btnNetpilotOptimize");
  const icon = document.getElementById("btnNetpilotOptIcon");
  const text = document.getElementById("btnNetpilotOptText");

  if (btn) btn.disabled = true;
  if (icon) icon.className = "inline-block animate-spin";
  if (text) text.textContent = "Optimizing Stack...";

  try {
    const res = await fetch("/api/netpilot/optimize_now", { method: "POST" });
    const data = await res.json();
    if (data.success) {
      showToast("Netpilot Optimization Complete", `Executed deep kernel tuning (${data.elapsed_ms}ms, latency ${data.latency_ms}ms)`, "success");
      if (data.metrics) {
        updateNetpilotUi({ metrics: data.metrics });
      }
      fetchNetpilotStatus();
    } else {
      showToast("Netpilot Optimization", data.message || "Completed", "info");
    }
  } catch (err) {
    showToast("Optimization Failed", "Could not complete kernel sweep", "danger");
  } finally {
    if (btn) btn.disabled = false;
    if (icon) icon.className = "";
    if (text) text.textContent = "Run Deep Optimization";
  }
}

// ===========================================================================
// ⏳ SMART AUTOMATION & TIME-SCHEDULER ENGINE CONTROLLER
// ===========================================================================

let _selectedTimerMinutes = 15;
let _activeTemplateKey = null;

async function fetchSchedulesAndTimers() {
  try {
    const [schedRes, timerRes, routRes] = await Promise.all([
      fetch("/api/schedules"),
      fetch("/api/schedules/timers"),
      fetch("/api/schedules/routines")
    ]);
    if (schedRes.ok) AppState.schedules = await schedRes.json();
    if (timerRes.ok) AppState.timers = await timerRes.json();
    if (routRes.ok) AppState.routines = await routRes.json();

    renderAutomationView();
  } catch (err) {
    console.error("[SwitchGate] Failed to fetch automation data:", err);
  }
}

function renderAutomationView() {
  renderActiveTimersUI(AppState.timers || []);
  renderSchedulesUI(AppState.schedules || []);
  updateRoutinesUI(AppState.routines || {});

  const totalAutomations = (AppState.schedules?.length || 0) + (AppState.timers?.length || 0);
  const sideSched = document.getElementById("sidebarAutomationCount");
  if (sideSched) sideSched.innerText = totalAutomations;
  const tBadge = document.getElementById("timerCountBadge");
  if (tBadge) tBadge.innerText = `${AppState.timers?.length || 0} Running`;
  const rBadge = document.getElementById("rulesCountBadge");
  if (rBadge) rBadge.innerText = `${AppState.schedules?.length || 0} Rules`;
}

function renderActiveTimersUI(timers) {
  const container = document.getElementById("activeTimersGrid");
  if (!container) return;

  if (!timers || timers.length === 0) {
    container.innerHTML = `
      <div class="col-span-full command-card p-6 border border-white/5 text-center text-slate-500 text-xs">
        No active countdown timers running. Click <button onclick="openQuickTimerModal()" class="text-cyan-400 font-bold underline hover:text-cyan-300">"Quick Sleep Timer"</button> above to auto-pause any device in 15m, 30m, 1h, or 2h.
      </div>
    `;
    return;
  }

  container.innerHTML = timers.map(t => {
    const isBlock = t.action === "BLOCK";
    const percent = typeof t.progress_percent === "number" ? t.progress_percent : 100;

    return `
      <div class="command-card p-4 border border-cyan-500/30 flex flex-col justify-between relative overflow-hidden shadow-lg shadow-cyan-950/30">
        <!-- Top Row -->
        <div class="flex items-start justify-between gap-3 mb-2">
          <div class="min-w-0">
            <h5 class="text-sm font-bold text-white truncate" title="${escapeHtml(t.name)}">${escapeHtml(t.name)}</h5>
            <div class="text-[11px] font-mono text-slate-400 truncate">${escapeHtml(t.ip || t.mac)}</div>
          </div>
          <span class="text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full ${isBlock ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30' : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'} flex-shrink-0">
            ${isBlock ? 'CUTOFF AT 00:00' : 'RESTORE AT 00:00'}
          </span>
        </div>

        <!-- Middle: Big Countdown Clock -->
        <div class="my-3 text-center">
          <div class="text-3xl font-black font-mono tracking-wider text-cyan-400 text-glow-cyan animate-pulse">
            ${escapeHtml(t.remaining_formatted || '00:00')}
          </div>
          <div class="text-[10px] font-mono text-slate-400 mt-0.5">Time Remaining (${t.duration_minutes}m Initial)</div>
        </div>

        <!-- Progress Bar -->
        <div class="timer-progress-bar mb-3">
          <div class="timer-progress-fill" style="width: ${percent}%;"></div>
        </div>

        <!-- Bottom Action Row -->
        <div class="pt-2 border-t border-white/5 flex items-center justify-between">
          <span class="text-[10px] font-mono text-slate-400">Action: <strong class="text-white">${escapeHtml(t.action)}</strong></span>
          <button onclick="cancelActiveTimer('${escapeHtml(t.mac)}')" class="px-2.5 py-1 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 hover:text-rose-200 text-xs font-bold transition">
            ✕ Cancel Timer
          </button>
        </div>
      </div>
    `;
  }).join("");
}

function renderSchedulesUI(schedules) {
  const container = document.getElementById("schedulesListGrid");
  if (!container) return;

  if (!schedules || schedules.length === 0) {
    container.innerHTML = `
      <div class="col-span-full command-card p-6 border border-white/5 text-center text-slate-500 text-xs">
        No recurring curfew rules created yet. Click <button onclick="openAddScheduleModal()" class="text-cyan-400 font-bold underline hover:text-cyan-300">"New Schedule Rule"</button> to automate bedtime internet cutoffs.
      </div>
    `;
    return;
  }

  container.innerHTML = schedules.map(s => {
    const isActive = !!s.is_active;

    return `
      <div class="command-card p-4 border ${isActive ? 'border-white/10' : 'border-white/5 opacity-60'} flex flex-col justify-between transition">
        <div>
          <!-- Top Row -->
          <div class="flex items-start justify-between gap-3 mb-2">
            <div class="min-w-0">
              <h5 class="text-sm font-bold text-white truncate" title="${escapeHtml(s.name)}">${escapeHtml(s.name)}</h5>
              <div class="text-[11px] font-mono text-slate-400 truncate">${escapeHtml(s.device_name || s.mac)}</div>
            </div>
            <label class="cyber-switch flex-shrink-0">
              <input type="checkbox" ${isActive ? 'checked' : ''} onchange="toggleScheduleActive(${s.id}, this.checked)">
              <span class="slider"></span>
            </label>
          </div>

          <!-- Time Window Badge -->
          <div class="bg-black/40 rounded-xl p-2.5 border border-white/5 my-2 flex items-center justify-between font-mono text-xs">
            <span class="text-slate-400">Curfew Window:</span>
            <span class="text-cyan-300 font-bold tracking-wider">${escapeHtml(s.start_time)} → ${escapeHtml(s.end_time)}</span>
          </div>

          <!-- Days Badge -->
          <div class="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Recurrence:</span>
            <span class="px-2 py-0.5 rounded-full bg-white/5 text-slate-300 font-bold border border-white/10">${escapeHtml(s.days || 'ALL')}</span>
          </div>
        </div>

        <!-- Bottom Action Row -->
        <div class="pt-2.5 mt-3 border-t border-white/5 flex items-center justify-between">
          <span class="text-[10px] font-mono ${isActive ? 'text-emerald-400' : 'text-slate-500'} font-bold">
            ${isActive ? '● Enforcing Curfew' : '○ Schedule Paused'}
          </span>
          <button onclick="deleteScheduleRule(${s.id})" title="Delete rule" class="p-1 rounded-lg text-slate-500 hover:text-rose-400 transition">
            🗑️
          </button>
        </div>
      </div>
    `;
  }).join("");
}

function updateRoutinesUI(routines) {
  if (!routines) return;

  if (routines.auto_scan) {
    const tScan = document.getElementById("rtAutoScanToggle");
    if (tScan) tScan.checked = !!routines.auto_scan.enabled;
    const nScan = document.getElementById("rtAutoScanNext");
    if (nScan) nScan.textContent = routines.auto_scan.enabled ? `In ${routines.auto_scan.next_formatted}` : "Disabled";
  }

  if (routines.auto_audit) {
    const tAudit = document.getElementById("rtAutoAuditToggle");
    if (tAudit) tAudit.checked = !!routines.auto_audit.enabled;
    const nAudit = document.getElementById("rtAutoAuditNext");
    if (nAudit) nAudit.textContent = routines.auto_audit.enabled ? `In ${routines.auto_audit.next_formatted}` : "Disabled";
  }

  if (routines.auto_quarantine) {
    const tQuar = document.getElementById("rtAutoQuarantineToggle");
    if (tQuar) tQuar.checked = !!routines.auto_quarantine.enabled;
    const sQuar = document.getElementById("rtAutoQuarantineStatus");
    if (sQuar) sQuar.textContent = routines.auto_quarantine.enabled ? "Active Drop Shield" : "Zero-Trust Ready";
  }
}

function populateDeviceDropdown(selectId) {
  const sel = document.getElementById(selectId);
  if (!sel) return;

  const devs = AppState.devices || [];
  if (devs.length === 0) {
    sel.innerHTML = `<option value="">No devices detected (Rescan router)</option>`;
    return;
  }

  sel.innerHTML = devs.map(d => {
    const name = d.custom_name || d.vendor || d.ip || d.mac;
    return `<option value="${escapeHtml(d.mac)}">${escapeHtml(name)} (${escapeHtml(d.ip)})</option>`;
  }).join("");
}

// Modal Handlers
function openAddScheduleModal() {
  populateDeviceDropdown("schedTargetDevice");
  openModal("modalAddSchedule");
}

async function submitNewScheduleRule() {
  const mac = document.getElementById("schedTargetDevice")?.value;
  const name = document.getElementById("schedRuleName")?.value.trim();
  const startTime = document.getElementById("schedStartTime")?.value;
  const endTime = document.getElementById("schedEndTime")?.value;
  const days = document.getElementById("schedDays")?.value || "ALL";

  if (!mac || !startTime || !endTime) {
    showToast("Invalid Input", "Please select a device and set start/end times", "warning");
    return;
  }

  const ruleName = name || `Curfew (${startTime} - ${endTime})`;

  try {
    const res = await fetch("/api/schedules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mac, name: ruleName, start_time: startTime, end_time: endTime, days })
    });
    const data = await res.json();
    closeModal("modalAddSchedule");
    showToast("Schedule Activated", data.message, "success");
    fetchSchedulesAndTimers();
  } catch (err) {
    showToast("Error", "Failed to create schedule rule", "danger");
  }
}

async function toggleScheduleActive(id, enabled) {
  try {
    const res = await fetch(`/api/schedules/${id}/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ is_active: enabled })
    });
    const data = await res.json();
    showToast("Schedule Updated", enabled ? "Curfew rule activated" : "Curfew rule paused", "success");
    fetchSchedulesAndTimers();
  } catch (err) {
    showToast("Error", "Failed to toggle schedule", "danger");
  }
}

async function deleteScheduleRule(id) {
  try {
    const res = await fetch(`/api/schedules/${id}`, { method: "DELETE" });
    const data = await res.json();
    showToast("Schedule Deleted", data.message, "info");
    fetchSchedulesAndTimers();
  } catch (err) {
    showToast("Error", "Failed to delete schedule rule", "danger");
  }
}

function openQuickTimerModal() {
  populateDeviceDropdown("timerTargetDevice");
  selectTimerPreset(15);
  openModal("modalQuickTimer");
}

function selectTimerPreset(mins, btn) {
  _selectedTimerMinutes = mins;
  const input = document.getElementById("timerCustomMins");
  if (input) input.value = mins;

  document.querySelectorAll(".timer-preset-btn").forEach(b => {
    b.className = "timer-preset-btn py-2 rounded-xl bg-white/5 text-slate-300 border border-white/10 font-bold hover:bg-white/10";
  });
  if (btn) {
    btn.className = "timer-preset-btn active py-2 rounded-xl bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold";
  }
}

async function submitQuickTimer() {
  const mac = document.getElementById("timerTargetDevice")?.value;
  const customMins = parseInt(document.getElementById("timerCustomMins")?.value, 10);
  const minutes = (!isNaN(customMins) && customMins > 0) ? customMins : _selectedTimerMinutes;
  const action = document.getElementById("timerAction")?.value || "BLOCK";

  if (!mac) {
    showToast("Invalid Input", "Please select a target device", "warning");
    return;
  }

  try {
    const res = await fetch("/api/schedules/timers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mac, minutes, action })
    });
    const data = await res.json();
    closeModal("modalQuickTimer");
    showToast("Sleep Timer Started", data.message, "success");
    fetchSchedulesAndTimers();
  } catch (err) {
    showToast("Error", "Failed to start sleep timer", "danger");
  }
}

async function cancelActiveTimer(mac) {
  try {
    const res = await fetch(`/api/schedules/timers/${encodeURIComponent(mac)}`, { method: "DELETE" });
    const data = await res.json();
    showToast("Timer Cancelled", data.message, "info");
    fetchSchedulesAndTimers();
  } catch (err) {
    showToast("Error", "Failed to cancel sleep timer", "danger");
  }
}

const TEMPLATE_PRESETS = {
  kids_bedtime: {
    icon: "🌙",
    name: "Kids Bedtime Curfew",
    desc: "Disconnects smartphones and gaming consoles overnight every day (22:00 – 06:00).",
    hours: "Time: 22:00 – 06:00 (Every Day)"
  },
  study_focus: {
    icon: "📚",
    name: "Study Focus Window",
    desc: "Enforces focused study periods on weekdays (Mon–Fri), pausing entertainment gadgets (14:00 – 17:00).",
    hours: "Time: 14:00 – 17:00 (Weekdays Only)"
  },
  night_saver: {
    icon: "🔋",
    name: "Overnight Wi-Fi Saver",
    desc: "Quenches idle smart TVs, IoT appliances, and background streaming during graveyard hours (01:00 – 06:30).",
    hours: "Time: 01:00 – 06:30 (Every Day)"
  }
};

function applyTemplatePreset(templateKey) {
  _activeTemplateKey = templateKey;
  const tpl = TEMPLATE_PRESETS[templateKey];
  if (!tpl) return;

  const iconEl = document.getElementById("tplModalIcon");
  if (iconEl) iconEl.textContent = tpl.icon;
  const nameEl = document.getElementById("tplModalName");
  if (nameEl) nameEl.textContent = tpl.name;
  const descEl = document.getElementById("tplModalDesc");
  if (descEl) descEl.textContent = tpl.desc;
  const hoursEl = document.getElementById("tplModalHours");
  if (hoursEl) hoursEl.textContent = tpl.hours;

  populateDeviceDropdown("tplTargetDevice");
  openModal("modalApplyTemplate");
}

async function submitApplyTemplate() {
  const mac = document.getElementById("tplTargetDevice")?.value;
  if (!mac || !_activeTemplateKey) {
    showToast("Invalid Input", "Please select a target device", "warning");
    return;
  }

  try {
    const res = await fetch("/api/schedules/templates/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mac, template_key: _activeTemplateKey })
    });
    const data = await res.json();
    closeModal("modalApplyTemplate");
    showToast("Template Applied", data.message, "success");
    fetchSchedulesAndTimers();
  } catch (err) {
    showToast("Error", "Failed to apply template", "danger");
  }
}

async function toggleAutonomousRoutine(routineKey, enabled) {
  try {
    const payload = {};
    if (routineKey === "auto_scan") payload.auto_scan_enabled = enabled;
    if (routineKey === "auto_audit") payload.auto_audit_enabled = enabled;
    if (routineKey === "auto_quarantine") payload.auto_quarantine_enabled = enabled;

    const res = await fetch("/api/schedules/routines", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    showToast("Routine Updated", "Autonomous routine setting saved", "success");
    if (data.routines) updateRoutinesUI(data.routines);
  } catch (err) {
    showToast("Error", "Failed to update routine", "danger");
  }
}

// ===========================================================================
// 🌐 GOOGLE WORKSPACE ENTERPRISE CLOUD BRIDGE CONTROLLER
// ===========================================================================

async function loadWorkspaceSettingsUI() {
  try {
    const res = await fetch("/api/workspace/config");
    if (!res.ok) return;
    const cfg = await res.json();

    const whEl = document.getElementById("wsSettingWebhookUrl");
    if (whEl && cfg.webhook_url) whEl.value = cfg.webhook_url;

    const calEl = document.getElementById("wsSettingCalendarUrl");
    if (calEl && cfg.calendar_feed_url) calEl.value = cfg.calendar_feed_url;

    const autoAlertEl = document.getElementById("wsSettingAutoAlert");
    if (autoAlertEl) autoAlertEl.checked = !!cfg.auto_alert_intruders;

    const autoCalEl = document.getElementById("wsSettingAutoCalendar");
    if (autoCalEl) autoCalEl.checked = !!cfg.auto_calendar_sync;
  } catch (err) {
    console.error("[Workspace Bridge] Failed to load config:", err);
  }
}

async function saveWorkspaceSetting(key, val) {
  try {
    const payload = {};
    payload[key] = val;
    const res = await fetch("/api/workspace/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      showToast("Workspace Config Saved", `Google Workspace setting updated`, "success");
    }
  } catch (err) {
    showToast("Error", "Failed to save Google Workspace setting", "danger");
  }
}

async function testWorkspaceWebhook() {
  const url = document.getElementById("wsSettingWebhookUrl")?.value.trim();
  if (url) {
    await saveWorkspaceSetting("webhook_url", url);
  }

  showToast("Dispatching Alert", "Sending card to Google Chat...", "info");
  try {
    const res = await fetch("/api/workspace/test-webhook", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "SwitchGate Security Test Alert",
        message: "Google Workspace enterprise integration active. Live telemetry and intrusion defense online.",
        alert_type: "SUCCESS"
      })
    });
    const data = await res.json();
    if (res.ok) {
      showToast("Alert Delivered", data.message, "success");
    } else {
      showToast("Webhook Error", data.detail || "Check Webhook URL", "warning");
    }
  } catch (err) {
    showToast("Connection Error", "Could not reach Google Chat webhook", "danger");
  }
}

async function syncWorkspaceCalendar() {
  const url = document.getElementById("wsSettingCalendarUrl")?.value.trim();
  if (url) {
    await saveWorkspaceSetting("calendar_feed_url", url);
  }

  showToast("Syncing Calendar", "Fetching Google Calendar events...", "info");
  try {
    const res = await fetch("/api/workspace/sync/calendar", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    const data = await res.json();
    if (res.ok) {
      showToast("Calendar Synced", data.message, "success");
      fetchSchedulesAndTimers();
    } else {
      showToast("Sync Notice", data.detail || "Verify iCal URL", "warning");
    }
  } catch (err) {
    showToast("Sync Failed", "Could not fetch Google Calendar feed", "danger");
  }
}

function exportToGoogleSheets() {
  showToast("Google Sheets Export", "Compiling live devices CSV...", "info");
  window.location.href = "/api/workspace/export/sheets";
}

function exportAuditToGoogleSheets() {
  showToast("Audit Logs Export", "Compiling security logs CSV...", "info");
  window.location.href = "/api/workspace/export/audit";
}

async function generateGoogleDocsReport() {
  showToast("Compiling Report", "Formatting executive Google Docs audit...", "info");
  try {
    const res = await fetch("/api/workspace/export/docs-report");
    const data = await res.json();
    if (data.content) {
      const blob = new Blob([data.content], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `SwitchGate_GoogleDocs_AuditReport_${Date.now()}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast("Report Ready", "Downloaded Google Docs-formatted report (.md)", "success");
    }
  } catch (err) {
    showToast("Error", "Failed to generate Google Docs report", "danger");
  }
}

async function backupToGoogleDrive() {
  showToast("Drive Backup", "Packaging database snapshot...", "info");
  try {
    const res = await fetch("/api/workspace/backup/drive", { method: "POST" });
    const data = await res.json();
    if (data.payload) {
      const blob = new Blob([JSON.stringify(data.payload, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = data.filename || `SwitchGate_DriveBackup_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast("Drive Package Ready", `Backed up ${data.total_devices} devices & rules for Google Drive`, "success");
    }
  } catch (err) {
    showToast("Backup Failed", "Could not package Drive snapshot", "danger");
  }
}




