#pragma once

#include <Arduino.h>
#include <ESPAsyncWebServer.h>
#include "entropy.h"
#include "config.h"

/**
 * QRNGWebServer
 *
 * ESPAsyncWebServer-based local web interface for QRNGabri.
 *
 * Routes:
 *   GET  /             – Main dashboard (bias plot, FIFO display)
 *   GET  /config       – Wi-Fi & settings configuration page
 *   POST /config       – Save config (JSON body)
 *   GET  /api/status   – JSON: bias, fifo size, total bits, modular_sum
 *   GET  /api/fifo     – JSON: last N bits array
 *   GET  /api/config   – JSON: current config (no passwords)
 */

class QRNGWebServer {
public:
    /**
     * @param port        HTTP port (default 80)
     * @param entropy     Reference to the entropy engine (for live data)
     * @param config      Reference to the device config (for display & save)
     * @param bleConnected Pointer to a flag indicating BLE connection status
     */
    QRNGWebServer(uint16_t port, EntropyEngine& entropy,
                  DeviceConfig& config, bool* bleConnected);

    void begin();

private:
    AsyncWebServer  m_server;
    EntropyEngine&  m_entropy;
    DeviceConfig&   m_config;
    bool*           m_bleConnected;

    void registerRoutes();
    void handleRoot(AsyncWebServerRequest* req);
    void handleConfigPage(AsyncWebServerRequest* req);
    void handleConfigSave(AsyncWebServerRequest* req, uint8_t* data,
                          size_t len, size_t index, size_t total);
    void handleStatus(AsyncWebServerRequest* req);
    void handleFIFO(AsyncWebServerRequest* req);
    void handleGetConfig(AsyncWebServerRequest* req);
};
