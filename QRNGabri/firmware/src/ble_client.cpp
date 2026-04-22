#include "ble_client.h"

// ─── Static members ───────────────────────────────────────────────────────────
RadonEyeBLEClient* RadonEyeBLEClient::s_instance = nullptr;
const uint8_t RadonEyeBLEClient::CMD_READ_DATA[] = {0x50};
const uint8_t RadonEyeBLEClient::CMD_READ_UPTIME[] = {0x51};

// ─── Scan callback ────────────────────────────────────────────────────────────
static std::string s_discoveredAddr = "";
static bool        s_deviceFound    = false;

class RD200ScanCallback : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) override {
        if (advertisedDevice.haveName()) {
            std::string name = advertisedDevice.getName();
            if (name.rfind(RadonEyeBLEClient::DEVICE_NAME_PREFIX, 0) == 0) {
                s_discoveredAddr = advertisedDevice.getAddress().toString();
                s_deviceFound    = true;
                BLEDevice::getScan()->stop();
                Serial.printf("[BLE] Found device: %s  addr: %s\n",
                              name.c_str(), s_discoveredAddr.c_str());
            }
        }
    }
};

// ─── Constructor / Destructor ─────────────────────────────────────────────────
RadonEyeBLEClient::RadonEyeBLEClient()
    : m_pClient(nullptr), m_pReadChar(nullptr), m_pWriteChar(nullptr),
    m_connected(false), m_protocolVersion(ProtocolVersion::Unknown),
    m_notifyLen(0), m_dataReady(false)
{
    s_instance = this;
    memset(m_notifyBuf, 0, sizeof(m_notifyBuf));
}

RadonEyeBLEClient::~RadonEyeBLEClient() {
    disconnect();
    if (s_instance == this) s_instance = nullptr;
}

// ─── Static scan ─────────────────────────────────────────────────────────────
std::string RadonEyeBLEClient::discoverDevice(unsigned long timeout_ms) {
    if (!BLEDevice::getInitialized()) {
        BLEDevice::init("QRNGabri");
    }

    s_discoveredAddr = "";
    s_deviceFound    = false;

    BLEScan* pScan = BLEDevice::getScan();
    pScan->setAdvertisedDeviceCallbacks(new RD200ScanCallback());
    pScan->setActiveScan(true);
    pScan->setInterval(100);
    pScan->setWindow(99);

    Serial.println("[BLE] Scanning for RadonEye device…");
    unsigned long start = millis();

    while (!s_deviceFound && (millis() - start) < timeout_ms) {
        pScan->start(5, false);
        if (!s_deviceFound) {
            Serial.println("[BLE] Not found yet, continuing scan…");
            delay(500);
        }
    }

    if (!s_deviceFound) {
        Serial.println("[BLE] No RadonEye found within timeout");
    }
    return s_discoveredAddr;
}

// ─── Connect ─────────────────────────────────────────────────────────────────
bool RadonEyeBLEClient::connect(const std::string& mac_address) {
    if (m_connected) return true;

    if (!BLEDevice::getInitialized()) {
        BLEDevice::init("QRNGabri");
    }

    delay(300);
    m_pClient = BLEDevice::createClient();
    m_pClient->setMTU(517);

    Serial.printf("[BLE] Connecting to %s\n", mac_address.c_str());

    for (int attempt = 0; attempt < 3; attempt++) {
        if (m_pClient->connect(BLEAddress(mac_address.c_str()))) break;
        Serial.printf("[BLE] Connection attempt %d failed\n", attempt + 1);
        delay(1000);
        if (attempt == 2) {
            Serial.println("[BLE] All connection attempts failed");
            return false;
        }
    }

    BLERemoteService* pSvc = nullptr;
    m_protocolVersion = ProtocolVersion::Unknown;

    // Prefer V2 protocol UUIDs first, then fallback to V1.
    pSvc = m_pClient->getService(SERVICE_UUID_V2);
    if (pSvc) {
        m_pReadChar  = pSvc->getCharacteristic(CHAR_UUID_READ_V2);
        m_pWriteChar = pSvc->getCharacteristic(CHAR_UUID_WRITE_V2);
        if (m_pReadChar && m_pWriteChar) {
            m_protocolVersion = ProtocolVersion::V2;
        }
    }

    if (m_protocolVersion == ProtocolVersion::Unknown) {
        pSvc = m_pClient->getService(SERVICE_UUID_V1);
        if (pSvc) {
            m_pReadChar  = pSvc->getCharacteristic(CHAR_UUID_READ_V1);
            m_pWriteChar = pSvc->getCharacteristic(CHAR_UUID_WRITE_V1);
            if (m_pReadChar && m_pWriteChar) {
                m_protocolVersion = ProtocolVersion::V1;
            }
        }
    }

    if (m_protocolVersion == ProtocolVersion::Unknown || !m_pReadChar || !m_pWriteChar) {
        Serial.println("[BLE] Compatible RadonEye service/characteristics not found (V1/V2)");
        m_pClient->disconnect();
        return false;
    }

    m_pReadChar->registerForNotify(notifyCallback);
    m_connected = true;
    Serial.printf("[BLE] Connected & ready (protocol=%s)\n",
                  m_protocolVersion == ProtocolVersion::V1 ? "V1" : "V2");
    return true;
}

// ─── State ────────────────────────────────────────────────────────────────────
bool RadonEyeBLEClient::isConnected() const {
    return m_connected && m_pClient && m_pClient->isConnected();
}

void RadonEyeBLEClient::disconnect() {
    if (m_pClient) {
        if (m_pClient->isConnected()) m_pClient->disconnect();
        delete m_pClient;
        m_pClient = nullptr;
    }
    m_pReadChar  = nullptr;
    m_pWriteChar = nullptr;
    m_connected  = false;
    m_protocolVersion = ProtocolVersion::Unknown;
}

// ─── Notify callback ──────────────────────────────────────────────────────────
void RadonEyeBLEClient::notifyCallback(BLERemoteCharacteristic* /*pChar*/,
                                        uint8_t* data, size_t length, bool /*isNotify*/) {
    if (!s_instance) return;
    size_t copyLen = length;
    if (copyLen > sizeof(s_instance->m_notifyBuf)) {
        copyLen = sizeof(s_instance->m_notifyBuf);
    }
    memcpy(s_instance->m_notifyBuf, data, copyLen);
    s_instance->m_notifyLen = copyLen;
    s_instance->m_dataReady = true;
}

// ─── Poll ─────────────────────────────────────────────────────────────────────
RadonEyeBLEClient::SensorReading RadonEyeBLEClient::poll(unsigned long timeout_ms) {
    SensorReading result{};
    result.valid = false;

    if (!isConnected()) return result;

    m_dataReady = false;
    m_notifyLen = 0;
    m_pWriteChar->writeValue(const_cast<uint8_t*>(CMD_READ_DATA), sizeof(CMD_READ_DATA), true);

    if (!waitForNotification(timeout_ms)) {
        Serial.println("[BLE] Notification timeout");
        return result;
    }

    return parseNotification(m_notifyBuf, m_notifyLen);
}

RadonEyeBLEClient::UptimeReading RadonEyeBLEClient::pollUptime(unsigned long timeout_ms) {
    UptimeReading result{};
    result.valid = false;

    if (!isConnected()) return result;

    m_dataReady = false;
    m_notifyLen = 0;
    m_pWriteChar->writeValue(const_cast<uint8_t*>(CMD_READ_UPTIME), sizeof(CMD_READ_UPTIME), true);

    if (!waitForNotification(timeout_ms)) {
        Serial.println("[BLE] Uptime notification timeout");
        return result;
    }

    return parseUptimeNotification(m_notifyBuf, m_notifyLen);
}

bool RadonEyeBLEClient::waitForNotification(unsigned long timeout_ms) {
    unsigned long start = millis();
    while (!m_dataReady && (millis() - start) < timeout_ms) {
        delay(10);
    }
    return m_dataReady;
}

RadonEyeBLEClient::SensorReading
RadonEyeBLEClient::parseNotification(const uint8_t* data, size_t length) {
    SensorReading r{};

    if (length >= 43) {
        // V2-like frame: Bq/m3 at [2..3], counts at [39..42].
        uint16_t radonRaw = static_cast<uint16_t>((data[3] << 8) | data[2]);
        r.radon_bq        = static_cast<float>(radonRaw);
        r.c_now           = static_cast<int16_t>((data[40] << 8) | data[39]);
        r.c_last          = static_cast<int16_t>((data[42] << 8) | data[41]);
        if (m_protocolVersion == ProtocolVersion::Unknown) {
            m_protocolVersion = ProtocolVersion::V2;
            Serial.println("[BLE] Auto-detected protocol from 0x50 frame: V2");
        }
    } else if (length >= 18) {
        // V1 frame: counts at [14..17], radon value is float pci/l at [2..5].
        float radonPci = 0.0f;
        memcpy(&radonPci, data + 2, sizeof(float));
        r.radon_bq = radonPci * 37.0f;
        r.c_now    = static_cast<int16_t>((data[15] << 8) | data[14]);
        r.c_last   = static_cast<int16_t>((data[17] << 8) | data[16]);
        if (m_protocolVersion == ProtocolVersion::Unknown) {
            m_protocolVersion = ProtocolVersion::V1;
            Serial.println("[BLE] Auto-detected protocol from 0x50 frame: V1");
        }
    } else if (length >= 12) {
        // Compact 0x50 frame variant observed in the field.
        // Uses Bq/m3 at [2..3] and counts at [8..11].
        uint16_t radonRaw = static_cast<uint16_t>((data[3] << 8) | data[2]);
        r.radon_bq        = static_cast<float>(radonRaw);
        r.c_now           = static_cast<int16_t>((data[9] << 8) | data[8]);
        r.c_last          = static_cast<int16_t>((data[11] << 8) | data[10]);
        Serial.println("[BLE] Parsed compact 12-byte 0x50 frame");
    } else {
        Serial.printf("[BLE] Data frame too short for 0x50 parsing: %u\n", static_cast<unsigned>(length));
        return r;
    }

    r.uptime_seconds  = 0;
    r.valid           = true;
    return r;
}

RadonEyeBLEClient::UptimeReading
RadonEyeBLEClient::parseUptimeNotification(const uint8_t* data, size_t length) {
    UptimeReading r{};
    r.valid = false;
    uint32_t uptimeMinutes = 0;

    if (length >= 47) {
        // Long response frame: uptime_minutes at offset 43 (little-endian uint32).
        uptimeMinutes =
            static_cast<uint32_t>(data[43]) |
            (static_cast<uint32_t>(data[44]) << 8) |
            (static_cast<uint32_t>(data[45]) << 16) |
            (static_cast<uint32_t>(data[46]) << 24);
        if (m_protocolVersion == ProtocolVersion::Unknown) {
            m_protocolVersion = ProtocolVersion::V2;
            Serial.println("[BLE] Auto-detected protocol from 0x51 frame: V2");
        }
    } else if (length >= 8) {
        // Short response frame compatibility: uptime_minutes at offset 4.
        uptimeMinutes =
            static_cast<uint32_t>(data[4]) |
            (static_cast<uint32_t>(data[5]) << 8) |
            (static_cast<uint32_t>(data[6]) << 16) |
            (static_cast<uint32_t>(data[7]) << 24);
        if (m_protocolVersion == ProtocolVersion::Unknown) {
            m_protocolVersion = ProtocolVersion::V1;
            Serial.println("[BLE] Auto-detected protocol from 0x51 frame: V1");
        }
    } else {
        Serial.printf("[BLE] Uptime frame too short: %u\n", static_cast<unsigned>(length));
        return r;
    }

    r.uptime_seconds = uptimeMinutes * 60u;
    r.valid = true;
    return r;
}
