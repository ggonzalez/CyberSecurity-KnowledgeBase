#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

#include "config.h"
#include "ble_client.h"
#include "entropy.h"
#include "webserver.h"

// ─── Global objects ───────────────────────────────────────────────────────────
static DeviceConfig      g_config;
static EntropyEngine     g_entropy;
static bool              g_bleConnected   = false;
static bool              g_staMode        = false;
static QRNGWebServer*    g_webServer      = nullptr;
static RadonEyeBLEClient g_bleClient;
static std::string       g_bleAddress     = "";
static volatile uint8_t  g_latestCounter8 = 0;
static constexpr uint32_t ENTROPY_POLL_INTERVAL_MS = 120000;
static constexpr uint32_t ENTROPY_MIN_ACCEPT_DELTA_SECONDS = 600;

// ─── Wi-Fi helpers ────────────────────────────────────────────────────────────
static bool connectSTA() {
    Serial.printf("[WiFi] Connecting to '%s'…\n", g_config.wifi_ssid.c_str());
    WiFi.mode(WIFI_STA);
    WiFi.begin(g_config.wifi_ssid.c_str(), g_config.wifi_password.c_str());

    for (int i = 0; i < 40 && WiFi.status() != WL_CONNECTED; i++) {
        delay(500);
        Serial.print('.');
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("[WiFi] STA connected – IP: %s\n", WiFi.localIP().toString().c_str());
        return true;
    }
    Serial.println("[WiFi] STA connection failed");
    return false;
}

static void startAP() {
    const char* apSSID = "QRNGabri";
    Serial.printf("[WiFi] Starting AP '%s'\n", apSSID);
    WiFi.mode(WIFI_AP);
    WiFi.softAP(apSSID);
    Serial.printf("[WiFi] AP IP: %s\n", WiFi.softAPIP().toString().c_str());
}

// ─── Backend upload helper ────────────────────────────────────────────────────
/**
 * POST a 16-bit entropy packet to the backend.
 * Returns true on HTTP 200/201.
 */
static bool uploadPacket(uint16_t value, uint8_t counter8) {
    if (g_config.backend_url.isEmpty() || g_config.backend_psk.isEmpty()) {
        Serial.println("[Upload] Skipped: backend_url/backend_psk missing in config");
        return false;
    }
    if (WiFi.status() != WL_CONNECTED && g_staMode) {
        Serial.printf("[Upload] Skipped: STA not connected (WiFi.status=%d)\n", WiFi.status());
        return false;
    }

    HTTPClient http;
    String url = g_config.backend_url;
    if (!url.endsWith("/")) url += "/";
    url += "push";

    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    // PSK bearer token
    http.addHeader("Authorization", "Bearer " + g_config.backend_psk);
    http.setTimeout(8000);

    StaticJsonDocument<160> doc;
    doc["value"]     = value;
    doc["c_counter_8bit"] = counter8;
    doc["device_id"] = WiFi.macAddress();
    String body;
    serializeJson(doc, body);

    Serial.printf("[Upload] POST %s | value=0x%04X c8=0x%02X device_id=%s\n",
                  url.c_str(), value, counter8, WiFi.macAddress().c_str());

    int code = http.POST(body);
    String resp = http.getString();
    http.end();

    if (code == 200 || code == 201) {
        Serial.printf("[Upload] Success HTTP %d | response=%s\n", code, resp.c_str());
        return true;
    }
    Serial.printf("[Upload] ERROR HTTP %d for packet 0x%04X | response=%s\n",
                  code, value, resp.c_str());
    return false;
}

/**
 * Quick connectivity/auth check to backend ping endpoint.
 * Sends mock payload and expects HTTP 200.
 */
static bool pingBackend() {
    if (g_config.backend_url.isEmpty() || g_config.backend_psk.isEmpty()) {
        Serial.println("[Ping] Skipped: backend_url/backend_psk missing in config");
        return false;
    }
    if (WiFi.status() != WL_CONNECTED) {
        Serial.printf("[Ping] Skipped: STA not connected (WiFi.status=%d)\n", WiFi.status());
        return false;
    }

    HTTPClient http;
    String url = g_config.backend_url;
    if (!url.endsWith("/")) url += "/";
    url += "ping";

    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("Authorization", "Bearer " + g_config.backend_psk);
    http.setTimeout(5000);

    StaticJsonDocument<256> doc;
    doc["device_id"] = WiFi.macAddress();
    JsonArray mockValues = doc.createNestedArray("mock_values");
    mockValues.add(0x1234);
    mockValues.add(0x5678);
    mockValues.add(0x9ABC);
    doc["note"] = "startup connectivity check";

    String body;
    serializeJson(doc, body);

    Serial.printf("[Ping] POST %s | device_id=%s\n", url.c_str(), WiFi.macAddress().c_str());
    int code = http.POST(body);
    String resp = http.getString();
    http.end();

    if (code == 200) {
        Serial.printf("[Ping] Success HTTP %d | response=%s\n", code, resp.c_str());
        return true;
    }

    Serial.printf("[Ping] ERROR HTTP %d | response=%s\n", code, resp.c_str());
    return false;
}

// ─── FreeRTOS tasks ───────────────────────────────────────────────────────────

/**
 * entropy_task – polls the RadonEye BLE periodically and feeds accepted C_last
 * values into the entropy engine.
 */
static void entropyTask(void* /*pvParam*/) {
    TickType_t lastWake = xTaskGetTickCount();
    static bool hasAcceptedUptime = false;
    static uint32_t lastAcceptedUptimeSeconds = 0;
    static int16_t lastAcceptedCLast = 0;
    static bool entropyPrimed = false;

    while (true) {
        if (g_bleConnected) {
            auto reading = g_bleClient.poll(15000);
            auto uptime = g_bleClient.pollUptime(15000);

            if (reading.valid && uptime.valid) {
                Serial.printf("[BLE] Reading radon=%.2fBq c_now=%d c_last=%d uptime=%lus\n",
                              reading.radon_bq,
                              reading.c_now,
                              reading.c_last,
                              static_cast<unsigned long>(uptime.uptime_seconds));

                if (!entropyPrimed) {
                    g_latestCounter8 = static_cast<uint8_t>(reading.c_last) & 0xFFu;
                    g_entropy.feedCNow(reading.c_last); // Prime baseline; first call emits no bit.
                    entropyPrimed = true;
                    Serial.println("[Entropy] Baseline primed with current C_last");
                }

                if (!hasAcceptedUptime) {
                    lastAcceptedUptimeSeconds = uptime.uptime_seconds;
                    lastAcceptedCLast = reading.c_last;
                    g_latestCounter8 = static_cast<uint8_t>(reading.c_last) & 0xFFu;
                    hasAcceptedUptime = true;
                    Serial.println("[Entropy] First accepted sample reference captured; waiting for new C_last or 10-minute timeout");
                } else if (uptime.uptime_seconds < lastAcceptedUptimeSeconds) {
                    // Device likely rebooted or uptime counter reset; re-baseline uptime gate.
                    lastAcceptedUptimeSeconds = uptime.uptime_seconds;
                    lastAcceptedCLast = reading.c_last;
                    g_latestCounter8 = static_cast<uint8_t>(reading.c_last) & 0xFFu;
                    Serial.println("[Entropy] Uptime decreased/reset; re-baselining uptime gate");
                } else {
                    uint32_t elapsed = uptime.uptime_seconds - lastAcceptedUptimeSeconds;
                    bool cLastChanged = reading.c_last != lastAcceptedCLast;

                    if (cLastChanged || elapsed >= ENTROPY_MIN_ACCEPT_DELTA_SECONDS) {
                        int16_t previousCLast = lastAcceptedCLast;
                        lastAcceptedUptimeSeconds = uptime.uptime_seconds;
                        lastAcceptedCLast = reading.c_last;
                        g_latestCounter8 = static_cast<uint8_t>(reading.c_last) & 0xFFu;
                        g_entropy.feedCNow(reading.c_last);

                        if (cLastChanged && elapsed < ENTROPY_MIN_ACCEPT_DELTA_SECONDS) {
                            Serial.printf("[Entropy] C_last changed (%d -> %d) after %lus; accepted immediately and reset timer\n",
                                          previousCLast,
                                          reading.c_last,
                                          static_cast<unsigned long>(elapsed));
                        } else if (!cLastChanged) {
                            Serial.printf("[Entropy] C_last unchanged at %d for %lus; accepted due to timeout and reset timer\n",
                                          reading.c_last,
                                          static_cast<unsigned long>(elapsed));
                        } else {
                            Serial.printf("[Entropy] C_last changed (%d -> %d) after %lus; accepted and reset timer\n",
                                          previousCLast,
                                          reading.c_last,
                                          static_cast<unsigned long>(elapsed));
                        }
                    } else {
                        Serial.printf("[Entropy] C_last unchanged at %d; %lus/%lus elapsed, waiting\n",
                                      reading.c_last,
                                      static_cast<unsigned long>(elapsed),
                                      static_cast<unsigned long>(ENTROPY_MIN_ACCEPT_DELTA_SECONDS));
                    }
                }
            } else {
                Serial.println("[Entropy] BLE poll returned invalid reading or uptime");
                g_bleConnected = false;
                hasAcceptedUptime = false;
            }
        } else {
            // Attempt BLE reconnect
            Serial.println("[Entropy] BLE disconnected, scanning…");
            g_bleAddress = RadonEyeBLEClient::discoverDevice(30000);
            if (!g_bleAddress.empty()) {
                g_bleConnected = g_bleClient.connect(g_bleAddress);
                if (!g_bleConnected) {
                    Serial.println("[Entropy] Reconnect failed");
                }
            }
        }

        vTaskDelayUntil(&lastWake,
                        pdMS_TO_TICKS(ENTROPY_POLL_INTERVAL_MS));
    }
}

/**
 * upload_task – drains pending entropy packets to the backend.
 */
static void uploadTask(void* /*pvParam*/) {
    while (true) {
        if (g_entropy.pendingPackets() > 0) {
            EntropyPacket pkt{};
            if (g_entropy.popPacket(pkt)) {
                bool ok = uploadPacket(pkt.value, g_latestCounter8);
                if (ok) {
                    Serial.printf("[Upload] Sent packet 0x%04X\n", pkt.value);
                } else {
                    // Re-queue by resetting the sent flag (handled by NOT calling markSent)
                    // popPacket marks in-flight; if upload failed we need to retry next cycle.
                    // For simplicity: just log; packet is already dropped from queue.
                    // A more robust approach would use a retry ring buffer, but we keep it
                    // simple as lost packets are acceptable in QRNG — new entropy is generated
                    // constantly and 16-bit values have no sequential dependency.
                    Serial.printf("[Upload] Failed to send 0x%04X, dropping\n", pkt.value);
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// ─── setup() ─────────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n╔══════════════════════════╗");
    Serial.println("║   QRNGabri  v1.0         ║");
    Serial.println("║   Radon.   C-Pulse QRNG  ║");
    Serial.println("╚══════════════════════════╝");

    // ── Load config ──────────────────────────────────────────────────────────
    bool configOk = g_config.load();

    // Apply entropy config
    g_entropy.setModularSum(g_config.modular_sum, g_config.modular_sum_bits);

    // ── Network ──────────────────────────────────────────────────────────────
    if (configOk && g_config.isValid()) {
        g_staMode = connectSTA();
        if (g_staMode) {
            // Quick backend reachability/auth test after joining external AP.
            pingBackend();
        }
    }
    if (!g_staMode) {
        startAP();
    }

    // ── Web server ───────────────────────────────────────────────────────────
    g_webServer = new QRNGWebServer(80, g_entropy, g_config, &g_bleConnected);
    g_webServer->begin();

    // ── BLE scan ─────────────────────────────────────────────────────────────
    Serial.println("[Main] Starting BLE scan for RadonEye…");
    g_bleAddress = RadonEyeBLEClient::discoverDevice(30000);
    if (!g_bleAddress.empty()) {
        g_bleConnected = g_bleClient.connect(g_bleAddress);
        Serial.printf("[Main] BLE %s\n", g_bleConnected ? "connected" : "connection failed");
    } else {
        Serial.println("[Main] RadonEye not found – entropy task will retry");
    }

    // ── FreeRTOS tasks ───────────────────────────────────────────────────────
    xTaskCreatePinnedToCore(entropyTask, "entropy", 8192, nullptr, 2, nullptr, 0);
    xTaskCreatePinnedToCore(uploadTask,  "upload",  8192, nullptr, 1, nullptr, 0);

    Serial.println("[Main] QRNGabri ready.");
}

// ─── loop() ──────────────────────────────────────────────────────────────────
void loop() {
    // All work is in FreeRTOS tasks; loop only handles WiFi watchdog
    if (g_staMode && WiFi.status() != WL_CONNECTED) {
        Serial.println("[WiFi] Connection lost, reconnecting…");
        WiFi.reconnect();
        delay(5000);
    }
    delay(10000);
}
