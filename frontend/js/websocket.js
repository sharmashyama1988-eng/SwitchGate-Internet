/**
 * SwitchGate - Resilient WebSocket Client & Synchronization Engine v2.0
 * Real-time Bi-directional Communication, Bulletproof Reconnection & HTTP Fallback
 */

class SwitchGateSocket {
  constructor() {
    this.socket = null;
    this.reconnectAttempts = 0;
    this.baseReconnectDelay = 800;
    this.maxReconnectDelay = 5000;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.heartbeatCheckTimer = null;
    this.fallbackPollTimer = null;
    
    this.subscribers = {};
    this.isConnected = false;
    this.isFallbackActive = false;
    this.lastMessageTime = 0;
    this.heartbeatIntervalMs = 8000;
    this.heartbeatTimeoutMs = 15000;
    this.fallbackIntervalMs = 1500;
    
    this.status = "DISCONNECTED"; // DISCONNECTED | CONNECTING | CONNECTED | RECONNECTING | FALLBACK

    // Listen to network & tab visibility events
    if (typeof window !== "undefined") {
      window.addEventListener("online", () => {
        console.log("[SwitchGate WS] Network back online. Reconnecting immediately...");
        this.forceReconnect();
      });

      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible" && !this.isConnected) {
          console.log("[SwitchGate WS] Tab visible. Checking connection...");
          this.forceReconnect();
        }
      });
    }
  }

  _setStatus(newStatus, extraData = {}) {
    this.status = newStatus;
    this.emit("status", {
      status: newStatus,
      connected: this.isConnected,
      fallback: this.isFallbackActive,
      attempts: this.reconnectAttempts,
      ...extraData
    });
  }

  connect() {
    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this._setStatus("CONNECTING");

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host || "127.0.0.1:8000";
    const wsUrl = `${protocol}//${host}/ws`;

    try {
      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => {
        this.isConnected = true;
        this.isFallbackActive = false;
        this.reconnectAttempts = 0;
        this.lastMessageTime = Date.now();
        this._stopFallbackPolling();
        this._startHeartbeat();
        this._setStatus("CONNECTED", { url: wsUrl });
        console.log(`[SwitchGate WS] ⚡ Connected to live gateway stream at ${wsUrl}`);
      };

      this.socket.onmessage = (event) => {
        this.lastMessageTime = Date.now();
        try {
          const payload = JSON.parse(event.data);
          const eventType = payload.type || "message";
          
          if (eventType === "PONG") {
            // Heartbeat acknowledged
            return;
          }

          this.emit(eventType, payload);
          this.emit("message", payload);
        } catch (e) {
          console.error("[SwitchGate WS] JSON Parse / Handler error:", e);
        }
      };

      this.socket.onclose = (event) => {
        const wasClean = event && event.wasClean;
        const code = event ? event.code : 0;
        this.isConnected = false;
        this._stopHeartbeat();
        this._setStatus("DISCONNECTED", { code, wasClean });
        console.warn(`[SwitchGate WS] Connection closed (code: ${code}). Scheduling reconnect...`);
        this.scheduleReconnect();
      };

      this.socket.onerror = (err) => {
        console.warn("[SwitchGate WS] Socket encountered error event:", err);
      };
    } catch (err) {
      console.error("[SwitchGate WS] Connection instantiation error:", err);
      this.scheduleReconnect();
    }
  }

  forceReconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.socket) {
      try {
        this.socket.onopen = null;
        this.socket.onmessage = null;
        this.socket.onclose = null;
        this.socket.onerror = null;
        this.socket.close();
      } catch (e) {}
      this.socket = null;
    }
    this.isConnected = false;
    this.connect();
  }

  scheduleReconnect() {
    if (this.reconnectTimer) return;

    this.reconnectAttempts++;
    this._startFallbackPolling();

    // Jittered Exponential Backoff: delay = min(maxDelay, baseDelay * (1.3 ^ attempts)) + random jitter
    const rawDelay = this.baseReconnectDelay * Math.pow(1.3, Math.min(this.reconnectAttempts, 12));
    const jitter = Math.random() * 300;
    const delay = Math.min(rawDelay + jitter, this.maxReconnectDelay);

    this._setStatus("RECONNECTING", { nextRetryInMs: Math.round(delay) });

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  _startHeartbeat() {
    this._stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.isConnected && this.socket && this.socket.readyState === WebSocket.OPEN) {
        try {
          this.socket.send(JSON.stringify({ action: "PING", timestamp: Date.now() }));
        } catch (e) {
          console.warn("[SwitchGate WS] Failed to send heartbeat PING:", e);
        }
      }
    }, this.heartbeatIntervalMs);

    this.heartbeatCheckTimer = setInterval(() => {
      if (this.isConnected) {
        const timeSinceLastMsg = Date.now() - this.lastMessageTime;
        if (timeSinceLastMsg > this.heartbeatTimeoutMs) {
          console.warn(`[SwitchGate WS] Heartbeat timeout (${timeSinceLastMsg}ms since last packet). Reconnecting...`);
          this.forceReconnect();
        }
      }
    }, this.heartbeatIntervalMs);
  }

  _stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.heartbeatCheckTimer) {
      clearInterval(this.heartbeatCheckTimer);
      this.heartbeatCheckTimer = null;
    }
  }

  // --- Fallback Polling Engine ---
  _startFallbackPolling() {
    if (this.fallbackPollTimer || this.isConnected) return;
    this.isFallbackActive = true;
    this._setStatus("FALLBACK");
    console.log("[SwitchGate WS] 🔄 Fallback HTTP Polling engaged to maintain 100% live telemetry.");

    const pollTask = async () => {
      if (this.isConnected) {
        this._stopFallbackPolling();
        return;
      }
      try {
        const res = await fetch("/api/telemetry/live");
        if (res.ok) {
          const payload = await res.json();
          this.emit("TICK", payload);
          this.emit("message", payload);
        }
      } catch (err) {
        // Silent fallback error suppression
      }
    };

    pollTask(); // Run immediate first cycle
    this.fallbackPollTimer = setInterval(pollTask, this.fallbackIntervalMs);
  }

  _stopFallbackPolling() {
    if (this.fallbackPollTimer) {
      clearInterval(this.fallbackPollTimer);
      this.fallbackPollTimer = null;
    }
    this.isFallbackActive = false;
  }

  send(data) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      try {
        this.socket.send(typeof data === "string" ? data : JSON.stringify(data));
        return true;
      } catch (e) {
        console.warn("[SwitchGate WS] Send error:", e);
        return false;
      }
    }
    return false;
  }

  on(event, callback) {
    if (typeof callback !== "function") return;
    if (!this.subscribers[event]) {
      this.subscribers[event] = [];
    }
    this.subscribers[event].push(callback);
  }

  off(event, callback) {
    if (!this.subscribers[event]) return;
    if (!callback) {
      delete this.subscribers[event];
      return;
    }
    this.subscribers[event] = this.subscribers[event].filter((cb) => cb !== callback);
  }

  emit(event, data) {
    if (this.subscribers[event]) {
      // Execute each listener with an isolated error boundary
      for (const cb of this.subscribers[event]) {
        try {
          cb(data);
        } catch (err) {
          console.error(`[SwitchGate WS Error Boundary] Handler error for '${event}':`, err);
        }
      }
    }
  }

  getStatus() {
    return {
      status: this.status,
      connected: this.isConnected,
      fallback: this.isFallbackActive,
      reconnectAttempts: this.reconnectAttempts
    };
  }
}

window.sgSocket = new SwitchGateSocket();
