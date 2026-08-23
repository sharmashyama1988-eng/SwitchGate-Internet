/**
 * SwitchGate - Live 60 FPS Cyber Bandwidth & Kernel Hypervisor Waveform Canvas
 * Renders 3 real-time glowing bezier waveforms:
 *   1. Neon Cyan (#00f0ff)   - Inbound / Download Bandwidth Waveform
 *   2. Emerald Green (#00ff88) - kPerf Kernel Ring Buffer & Packet Shadows
 *   3. Neon Coral Red (#ff3366) - Outbound / Upload Bandwidth & Active Sockets
 */

class BandwidthWaveformEngine {
  constructor(canvasId) {
    this.canvasId = canvasId;
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas ? this.canvas.getContext("2d") : null;
    
    // Ring Buffers for 3 Streams (40 data points each)
    this.numPoints = 36;
    this.streamCyan = new Float32Array(this.numPoints).fill(15);   // Download
    this.streamGreen = new Float32Array(this.numPoints).fill(25);  // kPerf Ring Buffer
    this.streamRed = new Float32Array(this.numPoints).fill(10);    // Upload

    // Target telemetry values updated by WebSocket
    this.targetDown = 0.0;
    this.targetUp = 0.0;
    this.targetKperf = 184;

    this.time = 0;
    this.isRunning = false;
    this.displayWidth = 800;
    this.displayHeight = 180;

    this.init();
  }

  init() {
    if (!this.canvas) {
      setTimeout(() => {
        this.canvas = document.getElementById(this.canvasId);
        if (this.canvas) {
          this.ctx = this.canvas.getContext("2d");
          this.setupResize();
          this.startLoop();
        }
      }, 200);
      return;
    }
    this.setupResize();
    this.startLoop();
  }

  setupResize() {
    const handleResize = () => {
      if (!this.canvas || !this.canvas.parentElement) return;
      const rect = this.canvas.parentElement.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      
      const width = Math.max(rect.width || 600, 300);
      const height = Math.max(rect.height || 180, 140);

      this.canvas.width = width * dpr;
      this.canvas.height = height * dpr;

      if (this.ctx) {
        this.ctx.resetTransform?.();
        this.ctx.scale(dpr, dpr);
      }

      this.displayWidth = width;
      this.displayHeight = height;
    };

    if (window.ResizeObserver && this.canvas.parentElement) {
      new ResizeObserver(() => handleResize()).observe(this.canvas.parentElement);
    }
    window.addEventListener("resize", handleResize);
    handleResize();
  }

  updateTelemetry(data) {
    if (!data) return;
    if (typeof data.download_mbps === "number") this.targetDown = data.download_mbps;
    if (typeof data.upload_mbps === "number") this.targetUp = data.upload_mbps;
    if (data.kperf) {
      if (typeof data.kperf.ring_buffer_in_flight === "number") {
        this.targetKperf = data.kperf.ring_buffer_in_flight;
      } else if (typeof data.kperf.packet_shadows === "number") {
        this.targetKperf = data.kperf.packet_shadows;
      } else if (typeof data.kperf.total_shadows_streamed === "number") {
        this.targetKperf = Math.min(200, data.kperf.total_shadows_streamed % 200);
      }
    }
  }

  startLoop() {
    if (this.isRunning) return;
    this.isRunning = true;

    const tick = () => {
      this.time += 0.045;
      this.updatePhysics();
      this.render();
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  updatePhysics() {
    // Shift points left
    for (let i = 0; i < this.numPoints - 1; i++) {
      this.streamCyan[i] = this.streamCyan[i + 1];
      this.streamGreen[i] = this.streamGreen[i + 1];
      this.streamRed[i] = this.streamRed[i + 1];
    }

    const t = this.time;
    // Harmonic Procedural Noise + Real Telemetry Modulation
    const downMod = Math.max(this.targetDown * 8.0, 12.0);
    const upMod = Math.max(this.targetUp * 10.0, 8.0);
    const kperfMod = 16.0 + Math.sin(t * 0.8) * 8.0;

    // Cyan (Download): dynamic flowing wave
    const cyanVal = 30 + Math.sin(t * 2.2) * (downMod * 0.7) + Math.cos(t * 1.3) * (downMod * 0.5) + (Math.sin(t * 4.1) * 6);
    // Green (kPerf): mid-frequency sharp pulse wave
    const greenVal = 45 + Math.sin(t * 1.6 + 1.2) * (kperfMod * 0.8) + Math.cos(t * 2.7) * (kperfMod * 0.4);
    // Red (Upload): low harmonic undulating wave
    const redVal = 20 + Math.cos(t * 1.8 + 2.5) * (upMod * 0.7) + Math.sin(t * 0.9) * (upMod * 0.4);

    this.streamCyan[this.numPoints - 1] = Math.max(5, Math.min(130, cyanVal));
    this.streamGreen[this.numPoints - 1] = Math.max(8, Math.min(140, greenVal));
    this.streamRed[this.numPoints - 1] = Math.max(4, Math.min(110, redVal));
  }

  render() {
    if (!this.canvas || !this.ctx) return;
    const ctx = this.ctx;
    const w = this.displayWidth;
    const h = this.displayHeight;

    if (w <= 0 || h <= 0) return;

    // Clear Canvas
    ctx.clearRect(0, 0, w, h);

    // 1. Subtle High-Tech Cyber Grid
    ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
    ctx.lineWidth = 1;
    for (let y = 30; y < h; y += 35) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }
    for (let x = 40; x < w; x += 60) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }

    // 2. Draw Stream 3: Neon Red Waveform (Upload / Sockets)
    this.drawSmoothWave(
      this.streamRed,
      "#ff3366",
      "rgba(255, 51, 102, 0.22)",
      "rgba(255, 51, 102, 0.0)",
      2.5,
      h - 10
    );

    // 3. Draw Stream 2: Emerald Green Waveform (kPerf Kernel Ring Buffer)
    this.drawSmoothWave(
      this.streamGreen,
      "#00ff88",
      "rgba(0, 255, 136, 0.20)",
      "rgba(0, 255, 136, 0.0)",
      2.8,
      h - 15
    );

    // 4. Draw Stream 1: Neon Cyan Waveform (Download Bandwidth)
    this.drawSmoothWave(
      this.streamCyan,
      "#00f0ff",
      "rgba(0, 240, 255, 0.28)",
      "rgba(0, 240, 255, 0.0)",
      3.2,
      h - 20
    );

    // 5. High-Tech Legend Overlay in Top-Right
    this.drawLegend(ctx, w);
  }

  drawSmoothWave(dataArray, strokeColor, gradStart, gradEnd, lineWidth, baseY) {
    const ctx = this.ctx;
    const w = this.displayWidth;
    const h = this.displayHeight;
    const step = w / (this.numPoints - 1);

    const points = [];
    for (let i = 0; i < this.numPoints; i++) {
      const val = dataArray[i];
      const y = baseY - (val / 140) * (h * 0.75);
      points.push({ x: i * step, y: Math.max(8, Math.min(h - 4, y)) });
    }

    if (points.length < 2) return;

    // Draw Smooth Bezier Spline Path
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);

    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i];
      const p1 = points[i + 1];
      const xc = (p0.x + p1.x) / 2;
      const yc = (p0.y + p1.y) / 2;
      ctx.quadraticCurveTo(p0.x, p0.y, xc, yc);
    }
    ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);

    // Stroke with Bloom Glow
    ctx.save();
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = lineWidth;
    ctx.shadowColor = strokeColor;
    ctx.shadowBlur = 14;
    ctx.stroke();
    ctx.restore();

    // Fill Gradient to Base
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();

    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    gradient.addColorStop(0, gradStart);
    gradient.addColorStop(1, gradEnd);
    ctx.fillStyle = gradient;
    ctx.fill();

    // Pulsing Glowing Head Marker on the leading edge
    const lead = points[points.length - 1];
    ctx.save();
    ctx.beginPath();
    ctx.arc(lead.x, lead.y, 4.5, 0, Math.PI * 2);
    ctx.fillStyle = "#ffffff";
    ctx.shadowColor = strokeColor;
    ctx.shadowBlur = 18;
    ctx.fill();
    ctx.restore();
  }

  drawLegend(ctx, w) {
    ctx.save();
    ctx.font = "700 10px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";

    // Cyan Legend
    ctx.fillStyle = "#00f0ff";
    ctx.fillText("● INBOUND (DL)", w - 180, 20);

    // Green Legend
    ctx.fillStyle = "#00ff88";
    ctx.fillText("● kPERF RING", w - 90, 20);

    // Red Legend
    ctx.fillStyle = "#ff3366";
    ctx.fillText("● OUTBOUND (UL)", w - 10, 20);

    ctx.restore();
  }
}

// Global initialization
window.bandwidthChart = null;
window.initBandwidthChart = function() {
  if (!window.bandwidthChart) {
    window.bandwidthChart = new BandwidthWaveformEngine("bandwidthCanvas");
  }
};

document.addEventListener("DOMContentLoaded", () => {
  window.initBandwidthChart();
});
