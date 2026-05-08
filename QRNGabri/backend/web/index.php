<?php
/**
 * QRNGabri – Dashboard
 * Futuristic QRNG health & random number display
 */
date_default_timezone_set('UTC');
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta name="theme-color" content="#060c18"/>
  <title>QRNGabri — Quantum RNG Dashboard</title>
  <link rel="icon" type="image/svg+xml" href="favicon.svg"/>

  <!-- Fonts (with fallback) -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">

  <!-- Chart.js + date adapter -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>

  <!-- Local styles -->
  <link rel="stylesheet" href="style.css"/>
</head>
<body>

<div class="app-wrapper">

  <!-- ── Header ──────────────────────────────────────────────────────────── -->
  <header class="header">
    <div>
      <div class="logo">&#9762; QRNGabri</div>
      <div class="logo-sub">Quantum Random Number Generator &mdash; Radon <span class="alpha-symbol">&#945;</span>-decay Entropy</div>
    </div>
    <div class="header-meta" style="align-self:flex-end">
      <div>METHOD &nbsp; <span>Slow-Clock LSB Extraction</span></div>
      <div>DOCS &nbsp; <span><a href="https://github.com/ggonzalez/CyberSecurity-KnowledgeBase/tree/main/QRNGabri" target="_blank" rel="noopener noreferrer" style="color:var(--neon2);text-decoration:none">GitHub Repository</a></span></div>
    </div>
  </header>

  <div style="padding:0.1rem 0 1rem 0;font-size:0.7rem;line-height:1.6;color:var(--text)">
    <div style="color:var(--neon);font-weight:bold;margin-bottom:0.5rem">REAL QUANTUM RNG</div>
    <div>
      This device generates true random numbers from the radioactive decay of Radon-222. When a Radon nucleus undergoes alpha decay, the exact moment of emission is governed by quantum mechanics and is fundamentally unpredictable. The RadonEye sensor detects individual decay events; our entropy engine extracts the pure randomness from decay timing via Slow-Clock LSB extraction, producing cryptographically-secure 16-bit random values. Unlike computational pseudo-random generators, this is authentic quantum randomness sourced directly from nature's quantum processes.
    </div>
  </div>

  <!-- ── Hero ────────────────────────────────────────────────────────────── -->
  <section class="hero">
    <div class="hero-label">&#9646; Last Generated Random Number</div>
    <div class="random-number" id="randomNumber">— LOADING —</div>
    <div class="random-sub">
      <div class="random-sub-item">
        DECIMAL<span id="randomDecimal">—</span>
      </div>
      <div class="random-sub-item">
        GENERATED AT<span id="randomTime">—</span>
      </div>
      <div class="random-sub-item">
        BIT LENGTH<span id="randomBitLength">32 bits</span>
      </div>
    </div>
    <div style="margin-top:1.2rem;font-size:0.6rem;color:var(--dim);letter-spacing:0.1em;word-break:break-all" id="randomBinary">—</div>
  </section>

  <!-- ── Top stats row ───────────────────────────────────────────────────── -->
  <div class="grid-3" style="margin-bottom:1.5rem">

    <!-- Health LED -->
    <div class="panel">
      <div class="panel-title">&#9646; Entropy Health</div>
      <div class="health-center">
        <div class="led-container led-green" id="ledContainer">
          <div class="led-ring"></div>
          <div class="led-core"></div>
          <div class="led-glass"></div>
        </div>
        <div class="health-label ok" id="healthLabel">LOADING…</div>
        <dl class="health-stats">
          <div><dt>QUALITY BIAS</dt><dd id="statBiasQuality">—</dd></div>
          <div><dt>RAW BIAS</dt><dd id="statBiasRaw">—</dd></div>
          <div><dt>CORR. BIAS</dt><dd id="statBiasCorrected">—</dd></div>
          <div><dt>TOTAL BITS</dt><dd id="statTotal">—</dd></div>
          <div><dt>ONES</dt><dd id="statOnes">—</dd></div>
          <div><dt>ZEROS</dt><dd id="statZeros">—</dd></div>
        </dl>
      </div>
    </div>

    <!-- Range stats -->
    <div class="panel" style="overflow:visible">
      <div class="panel-title">&#9642; Selected Range</div>
      <div class="chart-controls">
        <div>
          <label>FROM</label><br>
          <input type="date" id="dateFrom" class="input-dark" style="margin-top:0.3rem"/>
        </div>
        <div>
          <label>TO</label><br>
          <input type="date" id="dateTo" class="input-dark" style="margin-top:0.3rem"/>
        </div>
        <button id="applyRange" class="btn btn-primary" style="align-self:flex-end">APPLY</button>
      </div>
      <div class="chart-controls" style="margin-top:0.8rem">
        <div>
          <label>READING TYPE</label><br>
          <select id="readingBits" class="input-dark" style="margin-top:0.3rem">
            <option value="1" selected>1-bit (current entropy stream)</option>
            <option value="2">2-bit readings</option>
            <option value="3">3-bit readings</option>
            <option value="4">4-bit readings</option>
            <option value="5">5-bit readings</option>
            <option value="6">6-bit readings</option>
            <option value="7">7-bit readings</option>
            <option value="8">8-bit readings</option>
          </select>
        </div>
        <div>
          <label>QUALITY CHECK</label><br>
          <select id="qualityBiasType" class="input-dark" style="margin-top:0.3rem">
            <option value="raw" selected>Raw Bias</option>
            <option value="corrected">Corrected Bias (modular sum)</option>
          </select>
        </div>
      </div>
      <div style="display:flex;gap:2rem;margin-top:0.5rem">
        <div class="stat-block">
          <div class="stat-value" id="chartSamples">—</div>
          <div class="stat-label">Packets (range / total)</div>
        </div>
        <div class="stat-block">
          <div class="stat-value" id="chartBias" style="font-size:1.2rem">—</div>
          <div class="stat-label">Raw / Corrected Bias</div>
        </div>
      </div>
    </div>

    <!-- Device info -->
    <div class="panel">
      <div class="panel-title">&#9873; Device</div>
      <div style="font-size:0.72rem;line-height:2;color:var(--dim)">
        <div>TYPE &nbsp;<span style="color:var(--text)">ESP32-S3</span></div>
        <div>SENSOR &nbsp;<span style="color:var(--text)">RadonEye RD200V2</span></div>
        <div>PROTOCOL &nbsp;<span style="color:var(--text)">BLE 4.2</span></div>
        <div>SOURCE &nbsp; <span style="color:var(--text)">RadonEye RD200V2 &bull; BLE C-Pulse</span></div>
        <div>SERVER TIME &nbsp; <span id="serverTime" style="color:var(--text)"><?= gmdate('Y-m-d H:i:s') ?> UTC</span></div>
        <div>SERVICE UUID</div>
        <div style="color:var(--neon2);font-size:0.6rem;word-break:break-all">00001523-0000-1000-8000-00805f9b34fb</div>
      </div>
    </div>

  </div>

  <!-- ── Bias Trend Chart ────────────────────────────────────────────────── -->
  <div class="panel" style="margin-bottom:1.5rem">
    <div class="panel-title">&#9641; Accumulated Raw Bias — Measurement by Measurement</div>
    <div class="chart-wrapper">
      <canvas id="biasChart"></canvas>
    </div>
    <div style="font-size:0.62rem;color:var(--dim);margin-top:0.75rem;text-align:center;letter-spacing:0.1em">
      The line shows the accumulated absolute bias after each 16-bit measurement packet.
      Early measurements are noisy and not very meaningful; after a few hundred measurements the curve should start to stabilise.
      Green is healthy, orange is borderline, and red indicates the bias has moved outside the safe margin.
    </div>
  </div>

  <!-- ── Scatter Plot ────────────────────────────────────────────────────── -->
  <div class="panel" style="margin-bottom:1.5rem">
    <div class="panel-title">&#9633; Entropy Dispersion — 16-bit Values Over Time</div>
    <div class="chart-wrapper" style="height:300px">
      <canvas id="scatterChart"></canvas>
    </div>
    <div style="font-size:0.62rem;color:var(--dim);margin-top:0.75rem;text-align:center;letter-spacing:0.1em">
      Each dot is a 16-bit entropy packet. Good QRNG: dots uniformly scattered across the full [0, 65535] range.
    </div>
  </div>

  <!-- ── Recent Generated Numbers ───────────────────────────────────────── -->
  <div class="panel" style="margin-bottom:1.5rem">
    <div class="panel-title">&#9660; Recent Generated Random Numbers</div>
    <div style="overflow-x:auto">
      <table class="data-table">
        <thead>
          <tr>
            <th>Hex Value</th>
            <th>Decimal</th>
            <th>Bits</th>
            <th>Generated At (UTC)</th>
          </tr>
        </thead>
        <tbody id="randomTbody">
          <tr><td colspan="4" style="text-align:center;color:var(--dim);padding:2rem">Loading…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

</div><!-- /app-wrapper -->

<footer class="footer">
  &#9762; QRNGabri &mdash; True Quantum Randomness from Radon-222 Alpha Decay &mdash; MIT License
  <br>
  <a href="https://github.com/ggonzalez/CyberSecurity-KnowledgeBase/tree/main/QRNGabri" target="_blank" rel="noopener noreferrer" style="color:var(--neon2);text-decoration:none">
    Documentation and Open Source Repository
  </a>
</footer>

<!-- Clock update -->
<script>
  setInterval(function(){
    var d = new Date();
    var el = document.getElementById('serverTime');
    if(el) el.textContent = d.toISOString().replace('T',' ').slice(0,19) + ' UTC';
  }, 1000);

  setTimeout(function(){
    window.location.reload();
  }, 15 * 60 * 1000);
</script>

<!-- App logic -->
<script src="app.js"></script>

</body>
</html>
