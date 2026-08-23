/**
 * CrashPad Universal Frontend Library v2.0
 * Provides client-side Input Control, UI Resilience, LRU Cache, and Network Retries.
 */

window.CrashPad = {
  // 1. Throttling Algorithm (Button Submissions)
  throttle: function(fn, intervalMs = 1000) {
    let lastTime = 0;
    return function(...args) {
      const now = Date.now();
      if (now - lastTime >= intervalMs) {
        lastTime = now;
        return fn.apply(this, args);
      }
    };
  },

  // 2. Debouncing Algorithm (Search / Text Input)
  debounce: function(fn, waitMs = 300) {
    let timeout = null;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => fn.apply(this, args), waitMs);
    };
  },

  // 3. Single-Flight / LaunchMode Pattern (Prevent Duplicate Modals / In-Flight Requests)
  singleFlight: function(asyncFn) {
    let inFlightPromise = null;
    return async function(...args) {
      if (inFlightPromise) return inFlightPromise;
      inFlightPromise = asyncFn.apply(this, args).finally(() => {
        inFlightPromise = null;
      });
      return inFlightPromise;
    };
  },

  // 4. Exponential Backoff with Full Jitter
  retryWithBackoff: async function(asyncFn, maxRetries = 4, baseDelayMs = 500) {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await asyncFn();
      } catch (err) {
        if (attempt === maxRetries) throw err;
        const tempDelay = Math.min(10000, baseDelayMs * Math.pow(2, attempt));
        const jitter = Math.random() * tempDelay;
        await new Promise(res => setTimeout(res, jitter));
      }
    }
  },

  // 5. Client-Side LRU Cache
  LRUCache: class {
    constructor(capacity = 100) {
      this.capacity = capacity;
      this.cache = new Map();
    }
    get(key) {
      if (!this.cache.has(key)) return null;
      const val = this.cache.get(key);
      this.cache.delete(key);
      this.cache.set(key, val);
      return val;
    }
    put(key, val) {
      if (this.cache.has(key)) {
        this.cache.delete(key);
      } else if (this.cache.size >= this.capacity) {
        // Evict oldest (first key in map iterator)
        const oldestKey = this.cache.keys().next().value;
        this.cache.delete(oldestKey);
      }
      this.cache.set(key, val);
    }
  },

  // 6. Global Error Boundary & Crash Protection
  initErrorBoundary: function() {
    window.addEventListener("error", (e) => {
      console.warn("[CrashPad Browser Boundary] Intercepted Error:", e.message);
    });
    window.addEventListener("unhandledrejection", (e) => {
      console.warn("[CrashPad Browser Boundary] Intercepted Promise Rejection:", e.reason);
    });
    console.log("[CrashPad] Client-Side Resiliency Shield active.");
  }
};

// Auto-initialize browser error shield
window.CrashPad.initErrorBoundary();
