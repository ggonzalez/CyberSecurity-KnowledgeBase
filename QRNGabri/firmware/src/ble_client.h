#pragma once

#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEClient.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <string>

/**
 * RadonEyeBLEClient
 *
 * Minimal BLE client for RadonEye RD200 family (V1/V2 protocol variants).
 * Adapted from the radoneye project and focused on C-pulse acquisition for QRNG entropy.
 *
 * BLE Protocol (reverse-engineered):
 *   Service UUID  : 00001523-0000-1000-8000-00805f9b34fb
 *   Write char    : 00001524-0000-1000-8000-00805f9b34fb  (write 0x50 to request data)
 *   Notify char   : 00001525-0000-1000-8000-00805f9b34fb  (variable-length notification)
 *
 * Notification layout (variable-length, little-endian):
 *   [2-3]  : current radon (Bq/m^3, uint16 LE)
 *   [39-40]: C_now  (int16 LE) - pulse counter current
 *   [41-42]: C_last (int16 LE) - pulse counter previous
 */

class RadonEyeBLEClient {
public:
    static constexpr const char* DEVICE_NAME_PREFIX = "FR:";
    static constexpr const char* SERVICE_UUID       = "00001523-0000-1000-8000-00805f9b34fb";
    static constexpr const char* SERVICE_UUID_V1    = "00001523-1212-efde-1523-785feabcd123";
    static constexpr const char* SERVICE_UUID_V2    = "00001523-0000-1000-8000-00805f9b34fb";
    static constexpr const char* CHAR_UUID_READ     = "00001525-0000-1000-8000-00805f9b34fb";
    static constexpr const char* CHAR_UUID_WRITE    = "00001524-0000-1000-8000-00805f9b34fb";
    static constexpr const char* CHAR_UUID_READ_V1  = "00001525-1212-efde-1523-785feabcd123";
    static constexpr const char* CHAR_UUID_WRITE_V1 = "00001524-1212-efde-1523-785feabcd123";
    static constexpr const char* CHAR_UUID_READ_V2  = "00001525-0000-1000-8000-00805f9b34fb";
    static constexpr const char* CHAR_UUID_WRITE_V2 = "00001524-0000-1000-8000-00805f9b34fb";

    enum class ProtocolVersion : uint8_t {
        Unknown = 0,
        V1,
        V2,
    };

    struct SensorReading {
        float   radon_bq;        ///< Current radon level Bq/m³
        int16_t c_now;           ///< C_now pulse counter
        int16_t c_last;          ///< C_last pulse counter
        uint32_t uptime_seconds; ///< Device uptime from command 0x51
        bool    valid;
    };

    struct UptimeReading {
        uint32_t uptime_seconds;
        bool     valid;
    };

    RadonEyeBLEClient();
    ~RadonEyeBLEClient();

    /** Scan for a RadonEye and return its MAC address.  Returns "" on timeout. */
    static std::string discoverDevice(unsigned long timeout_ms = 30000);

    /** Connect to a known MAC address. Returns true on success. */
    bool connect(const std::string& mac_address);

    bool isConnected() const;
    void disconnect();
    ProtocolVersion protocolVersion() const { return m_protocolVersion; }

    /**
     * Poll the device for a fresh sensor reading.
     * Blocks until notification arrives (up to timeout_ms).
     * Returns invalid reading on error.
     */
    SensorReading poll(unsigned long timeout_ms = 10000);

    /** Poll the device for uptime (command 0x51, 16-byte response). */
    UptimeReading pollUptime(unsigned long timeout_ms = 10000);

private:
    static RadonEyeBLEClient* s_instance;
    static const uint8_t CMD_READ_DATA[];
    static const uint8_t CMD_READ_UPTIME[];

    BLEClient*              m_pClient;
    BLERemoteCharacteristic* m_pReadChar;
    BLERemoteCharacteristic* m_pWriteChar;
    bool                    m_connected;
    ProtocolVersion         m_protocolVersion;

    uint8_t m_notifyBuf[80];
    size_t  m_notifyLen;
    volatile bool m_dataReady;

    static void notifyCallback(BLERemoteCharacteristic* pChar,
                               uint8_t* data, size_t length, bool isNotify);

    bool waitForNotification(unsigned long timeout_ms);
    SensorReading parseNotification(const uint8_t* data, size_t length);
    UptimeReading parseUptimeNotification(const uint8_t* data, size_t length);
};
