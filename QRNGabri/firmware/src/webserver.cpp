#include "webserver.h"
#include <ArduinoJson.h>

// ─── HTML templates (stored in PROGMEM to save RAM) ──────────────────────────

static const char HTML_HEAD[] PROGMEM = R"rawhtml(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>QRNGabri</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    :root{--neon:#00ffcc;--neon2:#00aaff;--bg:#080d1a;--panel:#0f1629;--border:#1a2a4a;--text:#c8d8f0;--dim:#4a6080;}
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;min-height:100vh;padding:1rem}
    h1{font-family:'Orbitron',sans-serif;font-weight:900;color:var(--neon);letter-spacing:4px;font-size:clamp(1.2rem,4vw,2rem);text-shadow:0 0 20px var(--neon),0 0 40px var(--neon)}
    h2{font-family:'Orbitron',sans-serif;font-weight:700;color:var(--neon2);font-size:0.85rem;letter-spacing:3px;text-transform:uppercase;margin-bottom:0.75rem}
    .header{display:flex;align-items:center;gap:1rem;padding:0.5rem 0 1.5rem}
    .subtitle{color:var(--dim);font-size:0.7rem}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:1rem}
    .panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:1.25rem;position:relative;overflow:hidden}
    .panel::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--neon),transparent)}
    .stat{font-size:2.5rem;font-family:'Orbitron',sans-serif;font-weight:900;color:var(--neon);text-shadow:0 0 15px var(--neon)}
    .stat-label{color:var(--dim);font-size:0.65rem;letter-spacing:2px;text-transform:uppercase;margin-top:0.25rem}
    .bit-stream{display:flex;flex-wrap:wrap;gap:3px;max-height:120px;overflow:hidden}
    .bit{width:14px;height:14px;border-radius:2px;display:inline-block;transition:background 0.3s}
    .bit-1{background:var(--neon);box-shadow:0 0 6px var(--neon)}
    .bit-0{background:var(--border)}
    .nav{display:flex;gap:1rem;margin-bottom:1.5rem}
    .nav a{color:var(--neon2);text-decoration:none;font-size:0.8rem;letter-spacing:2px;padding:0.4rem 0.8rem;border:1px solid var(--border);border-radius:4px;transition:all 0.2s}
    .nav a:hover,.nav a.active{border-color:var(--neon2);color:var(--neon);background:rgba(0,255,204,0.05)}
    canvas{max-width:100%;height:200px !important}
  </style>
</head>
<body>
<div class="header">
  <div>
    <h1>&#9762; QRNGabri</h1>
    <div class="subtitle">Quantum Random Number Generator &mdash; RadonEye C-pulse entropy</div>
  </div>
</div>
<nav class="nav">
  <a href="/" class="active">Dashboard</a>
  <a href="/config">Configuration</a>
</nav>
)rawhtml";

static const char HTML_FOOT[] PROGMEM = R"rawhtml(
</body>
</html>
)rawhtml";

// ─── Config page HTML ─────────────────────────────────────────────────────────
static const char HTML_CONFIG[] PROGMEM = R"rawhtml(
<div class="panel" style="max-width:540px">
  <h2>&#9881; Device Configuration</h2>
  <form id="cfgForm" style="display:flex;flex-direction:column;gap:0.9rem">
    <div>
      <label style="font-size:0.7rem;color:var(--dim);letter-spacing:2px">WI-FI SSID</label>
      <input id="wifi_ssid" type="text" autocomplete="off"
             style="width:100%;background:#060b16;border:1px solid var(--border);color:var(--text);padding:0.5rem;border-radius:4px;font-family:inherit;margin-top:0.3rem"/>
    </div>
    <div>
      <label style="font-size:0.7rem;color:var(--dim);letter-spacing:2px">WI-FI PASSWORD</label>
      <input id="wifi_password" type="password" autocomplete="new-password"
             style="width:100%;background:#060b16;border:1px solid var(--border);color:var(--text);padding:0.5rem;border-radius:4px;font-family:inherit;margin-top:0.3rem"/>
    </div>
    <div>
      <label style="font-size:0.7rem;color:var(--dim);letter-spacing:2px">BACKEND URL</label>
      <input id="backend_url" type="text" placeholder="https://host/api"
             style="width:100%;background:#060b16;border:1px solid var(--border);color:var(--text);padding:0.5rem;border-radius:4px;font-family:inherit;margin-top:0.3rem"/>
    </div>
    <div>
          <label style="font-size:0.7rem;color:var(--dim);letter-spacing:2px">BACKEND RANDOM TOKEN (PSK)</label>
      <input id="backend_psk" type="password" autocomplete="new-password"
            placeholder="paste backend random token"
             style="width:100%;background:#060b16;border:1px solid var(--border);color:var(--text);padding:0.5rem;border-radius:4px;font-family:inherit;margin-top:0.3rem"/>
    </div>
    <div>
      <label style="font-size:0.7rem;color:var(--dim);letter-spacing:2px">POLL INTERVAL (ms)</label>
      <input id="poll_interval_ms" type="number" min="5000" max="60000" step="1000"
             style="width:100%;background:#060b16;border:1px solid var(--border);color:var(--text);padding:0.5rem;border-radius:4px;font-family:inherit;margin-top:0.3rem"/>
    </div>
    <div style="display:flex;align-items:center;gap:0.8rem">
      <input id="modular_sum" type="checkbox" style="width:18px;height:18px"/>
      <label for="modular_sum" style="font-size:0.75rem;letter-spacing:1px">Enable Modular Sum (XOR Debias)</label>
    </div>
    <div>
      <label style="font-size:0.7rem;color:var(--dim);letter-spacing:2px">MODULAR SUM BITS (2 or 4)</label>
      <input id="modular_sum_bits" type="number" min="2" max="4" step="2"
             style="width:120px;background:#060b16;border:1px solid var(--border);color:var(--text);padding:0.5rem;border-radius:4px;font-family:inherit;margin-top:0.3rem"/>
    </div>
    <button type="submit"
            style="background:linear-gradient(90deg,#00997a,var(--neon));border:none;color:#000;padding:0.65rem;border-radius:4px;font-family:'Orbitron',sans-serif;font-weight:700;letter-spacing:2px;cursor:pointer;font-size:0.8rem">
      SAVE &amp; REBOOT
    </button>
  </form>
  <div id="cfgStatus" style="margin-top:1rem;font-size:0.75rem;color:var(--neon)"></div>
</div>
<script>
  // Pre-fill from current config
  fetch('/api/config').then(r=>r.json()).then(d=>{
    document.getElementById('wifi_ssid').value        = d.wifi_ssid        || '';
    document.getElementById('backend_url').value      = d.backend_url      || '';
    document.getElementById('poll_interval_ms').value = d.poll_interval_ms || 10000;
    document.getElementById('modular_sum').checked    = d.modular_sum      || false;
    document.getElementById('modular_sum_bits').value = d.modular_sum_bits || 2;
  });

  document.getElementById('cfgForm').addEventListener('submit', function(e){
    e.preventDefault();
    var payload = {
      wifi_ssid:        document.getElementById('wifi_ssid').value,
      wifi_password:    document.getElementById('wifi_password').value,
      backend_url:      document.getElementById('backend_url').value,
      backend_psk:      document.getElementById('backend_psk').value,
      random_token:     document.getElementById('backend_psk').value,
      poll_interval_ms: parseInt(document.getElementById('poll_interval_ms').value),
      modular_sum:      document.getElementById('modular_sum').checked,
      modular_sum_bits: parseInt(document.getElementById('modular_sum_bits').value)
    };
    fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
      .then(r=>r.json())
      .then(d=>{
        document.getElementById('cfgStatus').textContent = d.status === 'ok'
          ? '✓ Saved. Rebooting in 3s...'
          : '✗ Error: ' + (d.message||'unknown');
      });
  });
</script>
)rawhtml";

// ─── Dashboard HTML (dynamic data via JS polling /api/status and /api/fifo) ──

static const char HTML_DASHBOARD[] PROGMEM = R"rawhtml(
<div class="grid">

  <!-- Bias indicator + stats -->
  <div class="panel">
    <h2>&#9650; Entropy Health</h2>
    <div style="display:flex;align-items:center;gap:1.5rem;margin-bottom:1rem">
      <div id="led" style="width:36px;height:36px;border-radius:50%;background:#003322;box-shadow:0 0 10px #003322;border:2px solid #006644;transition:all 0.5s"></div>
      <div>
        <div class="stat" id="biasVal">—</div>
        <div class="stat-label">Bias (|p(1)−0.5|, lower=better)</div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;font-size:0.72rem;color:var(--dim)">
      <div>FIFO BITS: <span id="fifoSize" style="color:var(--text)">—</span></div>
      <div>TOTAL BITS: <span id="totalBits" style="color:var(--text)">—</span></div>
      <div>BLE: <span id="bleConn" style="color:var(--text)">—</span></div>
      <div>MOD SUM: <span id="modSum" style="color:var(--text)">—</span></div>
    </div>
  </div>

  <!-- Last 200 bits visualised -->
  <div class="panel">
    <h2>&#9641; Last Bits</h2>
    <div class="bit-stream" id="bitStream"></div>
  </div>

  <!-- Bias chart -->
  <div class="panel" style="grid-column:1/-1">
    <h2>&#9642; Bit Distribution (last 1000)</h2>
    <canvas id="biasChart"></canvas>
  </div>

</div>

<script>
var biasCtx = document.getElementById('biasChart').getContext('2d');
var biasChart = new Chart(biasCtx, {
  type: 'bar',
  data: {
    labels: ['0','1'],
    datasets:[{
      label:'Count',
      data:[0,0],
      backgroundColor:['rgba(0,170,255,0.5)','rgba(0,255,204,0.5)'],
      borderColor:['#00aaff','#00ffcc'],
      borderWidth:1
    }]
  },
  options:{
    responsive:true,
    plugins:{legend:{display:false}},
    scales:{
      y:{
        ticks:{color:'#4a6080'},
        grid:{color:'rgba(26,42,74,0.8)'},
        beginAtZero:true
      },
      x:{ticks:{color:'#4a6080'},grid:{display:false}}
    }
  }
});

function updateLED(bias, modSum){
  var led = document.getElementById('led');
  if(bias<0.05 || (bias<0.2 && modSum)){
    led.style.background='#00ff88';
    led.style.boxShadow='0 0 20px #00ff88, 0 0 40px #00ff88';
    led.style.borderColor='#00ff88';
  } else {
    led.style.background='#ff4422';
    led.style.boxShadow='0 0 20px #ff4422, 0 0 40px #ff4422';
    led.style.borderColor='#ff6644';
  }
}

function refresh(){
  fetch('/api/status').then(r=>r.json()).then(d=>{
    var bias = d.bias !== undefined ? d.bias : 0.5;
    document.getElementById('biasVal').textContent  = bias.toFixed(4);
    document.getElementById('fifoSize').textContent = d.fifo_size;
    document.getElementById('totalBits').textContent= d.total_bits;
    document.getElementById('bleConn').textContent  = d.ble_connected ? '✓ OK' : '✗ DISCONNECTED';
    document.getElementById('bleConn').style.color  = d.ble_connected ? '#00ffcc' : '#ff4422';
    document.getElementById('modSum').textContent   = d.modular_sum ? 'ON (×' + d.modular_sum_bits + ')' : 'OFF';
    updateLED(bias, d.modular_sum);
  });

  fetch('/api/fifo?n=200').then(r=>r.json()).then(d=>{
    var bs = document.getElementById('bitStream');
    bs.innerHTML='';
    (d.bits||[]).forEach(function(b){
      var el=document.createElement('span');
      el.className='bit bit-'+b;
      el.title=b;
      bs.appendChild(el);
    });
    if(d.counts){
      biasChart.data.datasets[0].data=[d.counts[0]||0, d.counts[1]||0];
      biasChart.update('none');
    }
  });
}
refresh();
setInterval(refresh, 5000);
</script>
)rawhtml";

// ─── QRNGWebServer implementation ─────────────────────────────────────────────

QRNGWebServer::QRNGWebServer(uint16_t port, EntropyEngine& entropy,
                             DeviceConfig& config, bool* bleConnected)
    : m_server(port), m_entropy(entropy), m_config(config),
      m_bleConnected(bleConnected) {}

void QRNGWebServer::begin() {
    registerRoutes();
    m_server.begin();
    Serial.println("[Web] Server started on port 80");
}

void QRNGWebServer::registerRoutes() {
    // Main dashboard
    m_server.on("/", HTTP_GET, [this](AsyncWebServerRequest* req) {
        handleRoot(req);
    });

    // Config page (GET)
    m_server.on("/config", HTTP_GET, [this](AsyncWebServerRequest* req) {
        handleConfigPage(req);
    });

    // Config save (POST, JSON body via body handler)
    m_server.on("/config", HTTP_POST,
        [](AsyncWebServerRequest* req) {},   // empty handler – body handler below fires
        nullptr,
        [this](AsyncWebServerRequest* req, uint8_t* data, size_t len,
               size_t index, size_t total) {
            handleConfigSave(req, data, len, index, total);
        }
    );

    // API – status
    m_server.on("/api/status", HTTP_GET, [this](AsyncWebServerRequest* req) {
        handleStatus(req);
    });

    // API – FIFO bits
    m_server.on("/api/fifo", HTTP_GET, [this](AsyncWebServerRequest* req) {
        handleFIFO(req);
    });

    // API – current config (no passwords)
    m_server.on("/api/config", HTTP_GET, [this](AsyncWebServerRequest* req) {
        handleGetConfig(req);
    });

    m_server.onNotFound([](AsyncWebServerRequest* req) {
        req->send(404, "text/plain", "Not Found");
    });
}

void QRNGWebServer::handleRoot(AsyncWebServerRequest* req) {
    String html = FPSTR(HTML_HEAD);
    html += FPSTR(HTML_DASHBOARD);
    html += FPSTR(HTML_FOOT);
    req->send(200, "text/html", html);
}

void QRNGWebServer::handleConfigPage(AsyncWebServerRequest* req) {
    String html = FPSTR(HTML_HEAD);
    html += FPSTR(HTML_CONFIG);
    html += FPSTR(HTML_FOOT);
    req->send(200, "text/html", html);
}

void QRNGWebServer::handleConfigSave(AsyncWebServerRequest* req, uint8_t* data,
                                      size_t len, size_t /*index*/, size_t /*total*/) {
    StaticJsonDocument<512> doc;
    if (deserializeJson(doc, data, len)) {
        req->send(400, "application/json", "{\"status\":\"error\",\"message\":\"invalid JSON\"}");
        return;
    }

    // Validate and sanitise inputs
    String ssid     = doc["wifi_ssid"]    | "";
    String pass     = doc["wifi_password"]| "";
    String url      = doc["backend_url"]  | "";
    String psk      = doc["backend_psk"]  | "";
    if (psk.length() == 0) {
      psk          = doc["random_token"] | "";
    }
    uint32_t interval = doc["poll_interval_ms"] | 10000;

    // Basic input bounds
    if (interval < 5000)  interval = 5000;
    if (interval > 60000) interval = 60000;

    if (ssid.length() > 32 || pass.length() > 64 ||
        url.length() > 200 || psk.length() > 128) {
        req->send(400, "application/json",
                  "{\"status\":\"error\",\"message\":\"field too long\"}");
        return;
    }

    // Only update password fields if non-empty (allow keeping existing)
    if (ssid.length() > 0) m_config.wifi_ssid = ssid;
    if (pass.length() > 0) m_config.wifi_password = pass;
    if (url.length()  > 0) m_config.backend_url  = url;
    if (psk.length()  > 0) m_config.backend_psk  = psk;
    m_config.poll_interval_ms = interval;
    m_config.modular_sum      = doc["modular_sum"]      | false;
    m_config.modular_sum_bits = doc["modular_sum_bits"] | 2;

    bool ok = m_config.save();
    req->send(200, "application/json",
              ok ? "{\"status\":\"ok\"}" : "{\"status\":\"error\",\"message\":\"save failed\"}");

    if (ok) {
        // Reboot after a short delay to apply new config
        delay(1000);
        ESP.restart();
    }
}

void QRNGWebServer::handleStatus(AsyncWebServerRequest* req) {
    StaticJsonDocument<256> doc;
    doc["bias"]            = m_entropy.biasFraction();
    doc["fifo_size"]       = m_entropy.fifoSize();
    doc["total_bits"]      = m_entropy.totalBitsCollected();
    doc["ble_connected"]   = (m_bleConnected && *m_bleConnected);
    doc["modular_sum"]     = m_entropy.isModularSumEnabled();
    doc["modular_sum_bits"]= m_entropy.modularSumBits();
    doc["pending_packets"] = m_entropy.pendingPackets();

    String out;
    serializeJson(doc, out);
    req->send(200, "application/json", out);
}

void QRNGWebServer::handleFIFO(AsyncWebServerRequest* req) {
    // Optional ?n= parameter to limit count
    size_t n = 200;
    if (req->hasParam("n")) {
        long v = req->getParam("n")->value().toInt();
        if (v > 0 && v <= static_cast<long>(MAX_FIFO_BITS)) n = static_cast<size_t>(v);
    }

    uint8_t bits[MAX_FIFO_BITS];
    size_t  count = m_entropy.getFIFOBits(bits, n);

    // Build JSON manually to avoid large allocations
    String out = "{\"bits\":[";
    uint32_t ones = 0, zeros = 0;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) out += ',';
        out += bits[i] ? '1' : '0';
        if (bits[i]) ones++; else zeros++;
    }
    out += "],\"counts\":{\"0\":";
    out += zeros;
    out += ",\"1\":";
    out += ones;
    out += "}}";
    req->send(200, "application/json", out);
}

void QRNGWebServer::handleGetConfig(AsyncWebServerRequest* req) {
    StaticJsonDocument<256> doc;
    doc["wifi_ssid"]        = m_config.wifi_ssid;
    // Never expose passwords via API
    doc["backend_url"]      = m_config.backend_url;
    doc["token_set"]        = m_config.backend_psk.length() > 0;
    doc["poll_interval_ms"] = m_config.poll_interval_ms;
    doc["modular_sum"]      = m_config.modular_sum;
    doc["modular_sum_bits"] = m_config.modular_sum_bits;
    String out;
    serializeJson(doc, out);
    req->send(200, "application/json", out);
}
