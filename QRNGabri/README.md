# QRNGabri

**DIY Quantum Random Number Generator** using a RadonEye (RD200V2) radiation detector as the entropy source.

Documentation and open source repository: [https://github.com/ggonzalez/CyberSecurity-KnowledgeBase/tree/main/QRNGabri](https://github.com/ggonzalez/CyberSecurity-KnowledgeBase/tree/main/QRNGabri)

## Project PDF

<object data="./qrng.pdf" type="application/pdf" width="100%" height="720">
  <p>
    Your Markdown viewer does not support embedded PDFs.
    Open <a href="./qrng.pdf">qrng.pdf</a> directly.
  </p>
</object>

---

## What is it?

Radioactive decay is a fundamentally quantum process. The exact moment an atom decays cannot be predicted even in principle — it is governed by quantum mechanics, not classical determinism. QRNGabri harvests this intrinsic randomness by listening to the C-pulse counters on a [RadonEye RD200V2](https://www.radon-eye.com/) detector over BLE, extracts entropy bits using the **slow-clock method**, and feeds them into a PHP backend to generate and store true random numbers.

---

## Architecture

```
  ┌─────────────────────┐        BLE         ┌──────────────┐
  │  RadonEye RD200V2   │ ─────────────────→ │              │
  │  (alpha-decay puls.)│                    │   ESP32-S3   │
  └─────────────────────┘                    │   Firmware   │
                                             │              │
                                             └──────┬───────┘
                                                    │  HTTPS POST
                                                    │  (16-bit packets)
                                                    ▼
                                             ┌──────────────┐
                                             │  PHP Backend │
                                             │  REST API    │
                                             │  Dashboard   │
                                             └──────────────┘
```

---

## Components

### `firmware/` — ESP32-S3 PlatformIO Project

- **BLE client** — scans for `FR:` prefix devices, connects to RadonEye using V2 UUIDs first and V1 UUIDs as fallback, then parses `0x50`/`0x51` responses with protocol-aware offsets.
- **Entropy engine** — extracts the LSB of delta C-pulses each poll cycle (slow-clock method). Buffers up to 1000 bits in a FIFO ring buffer. Packs 16 bits into a `uint16_t` and queues for upload.
- **Config** — stored in LittleFS as `qrngabri.cfg` (JSON). Contains Wi-Fi credentials, backend URL, PSK token, poll interval, modular-sum settings.
- **Web UI** — ESPAsyncWebServer serving a local page with:
  - FIFO bit buffer visualisation + bias indicator
  - Wi-Fi configuration menu
  - Modular-sum (XOR debias) toggle
  - Live bit dispersion plot
- **Hotspot fallback** — if Wi-Fi config is missing or connection fails, device advertises `QRNGabri-Setup` AP and serves the config UI.

### `backend/` — PHP REST API + Dashboard

- **REST API** — PSK Bearer token auth, endpoints for entropy push, startup ping/auth connectivity checks, status, and random number retrieval.
- **Database** — MySQL/MariaDB with tables: `entropy_samples`, `generated_numbers`, `device_status`.
- **Dashboard** — futuristic dark-theme web UI featuring:
  - Large animated 32-bit random number display
  - Glowing health LED (green = good bias / red = uncompensated bias)
  - Accumulated raw bias line plot (Chart.js)
  - Entropy scatter plot (16-bit values over time)
  - Date-range selector for all historical views

---

## Entropy Method — Slow Clock

```
Every 2 minutes:
  1) Read normal sample with command 0x50 (C_now, C_last)
  2) Read uptime sample with command 0x51 (uptime minutes)
  3) If C_last changed since the last accepted sample: accept immediately and reset the timer
  4) If C_last did not change: wait until 10 minutes elapsed since the last accepted sample
  5) Once 10 minutes elapsed, accept the current C_last anyway and reset the timer
     delta = C_last(t) - C_last(t-1)
     entropy_bit = delta & 0b1      ← LSB of quantum count

Every 16 bits:
    packet = uint16_t(bit[0]..bit[15])
    if modular_sum_enabled:
        apply XOR-debias (N bits → 1 bit)
    POST packet to backend

On external AP connect:
  POST /api/ping with mock values to verify backend reachability + PSK auth
```

---

## Quick Start

### Firmware

1. Copy `firmware/data/qrngabri.cfg.example` to `firmware/data/qrngabri.cfg` and fill in your credentials.
2. Open in VS Code with PlatformIO.
3. `pio run -t uploadfs && pio run -t upload`

### Backend

Deployment instructions will be provided separately.

---

## Security

- PSK token must be ≥ 32 random characters.
- Backend uses constant-time `hash_equals()` for token validation.
- All API inputs are validated and sanitised.
- Use HTTPS in production.

---

## License

MIT
