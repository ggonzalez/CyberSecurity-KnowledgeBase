#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include <LittleFS.h>

/**
 * DeviceConfig
 *
 * Loads and persists the device configuration from/to LittleFS as "qrngabri.cfg" (JSON).
 *
 * Fields:
 *   wifi_ssid          – Wi-Fi network name
 *   wifi_password      – Wi-Fi password
 *   backend_url        – Full URL of the backend API base, e.g. https://host/api
 *   backend_psk        – Pre-shared key / random token for Bearer auth
 *   random_token       – Alias for backend_psk (accepted on load)
 *   poll_interval_ms   – BLE poll interval in milliseconds (default 10000)
 *   modular_sum        – Enable XOR debias (default false)
 *   modular_sum_bits   – Bits to XOR per output bit (2 or 4, default 2)
 */

static constexpr const char* CONFIG_PATH = "/qrngabri.cfg";

class DeviceConfig {
public:
    String  wifi_ssid;
    String  wifi_password;
    String  backend_url;
    String  backend_psk;
    uint32_t poll_interval_ms = 10000;
    bool    modular_sum       = false;
    uint8_t modular_sum_bits  = 2;

    /** Load config from LittleFS. Returns true if file was found and parseable. */
    bool load() {
        if (!LittleFS.begin(true)) {
            Serial.println("[Config] LittleFS mount failed");
            return false;
        }
        if (!LittleFS.exists(CONFIG_PATH)) {
            Serial.println("[Config] Config file not found");
            return false;
        }
        File f = LittleFS.open(CONFIG_PATH, "r");
        if (!f) {
            Serial.println("[Config] Failed to open config file");
            return false;
        }
        StaticJsonDocument<512> doc;
        DeserializationError err = deserializeJson(doc, f);
        f.close();
        if (err) {
            Serial.printf("[Config] JSON parse error: %s\n", err.c_str());
            return false;
        }
        wifi_ssid         = doc["wifi_ssid"]        | "";
        wifi_password     = doc["wifi_password"]    | "";
        backend_url       = doc["backend_url"]      | "";
        backend_psk       = doc["backend_psk"]      | "";
        if (backend_psk.length() == 0) {
            backend_psk   = doc["random_token"]     | "";
        }
        poll_interval_ms  = doc["poll_interval_ms"] | 10000;
        modular_sum       = doc["modular_sum"]      | false;
        modular_sum_bits  = doc["modular_sum_bits"] | 2;
        Serial.println("[Config] Loaded successfully");
        return true;
    }

    /** Save current values to LittleFS. Returns true on success. */
    bool save() {
        if (!LittleFS.begin(true)) return false;
        File f = LittleFS.open(CONFIG_PATH, "w");
        if (!f) return false;
        StaticJsonDocument<512> doc;
        doc["wifi_ssid"]         = wifi_ssid;
        doc["wifi_password"]     = wifi_password;
        doc["backend_url"]       = backend_url;
        doc["backend_psk"]       = backend_psk;
        doc["random_token"]      = backend_psk;
        doc["poll_interval_ms"]  = poll_interval_ms;
        doc["modular_sum"]       = modular_sum;
        doc["modular_sum_bits"]  = modular_sum_bits;
        serializeJson(doc, f);
        f.close();
        Serial.println("[Config] Saved successfully");
        return true;
    }

    /** True if the minimum required fields are filled in. */
    bool isValid() const {
        return wifi_ssid.length() > 0 &&
               backend_url.length() > 0 &&
               backend_psk.length() > 0;
    }
};
