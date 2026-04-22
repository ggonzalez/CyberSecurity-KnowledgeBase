#pragma once

#include <Arduino.h>
#include <stdint.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

/**
 * EntropyEngine
 *
 * Implements the slow-clock QRNG method using C-pulse counts from the RadonEye.
 *
 * Algorithm:
 *   1. Each BLE poll gives C_now (uint16).
 *   2. delta = C_now(t) − C_now(t−1)
 *   3. entropy_bit = delta & 0x01  (LSB of a quantum count)
 *   4. FIFO ring buffer stores the last MAX_FIFO_BITS raw bits.
 *   5. Every BITS_PER_PACKET bits, pack into a uint16_t and push to the send queue.
 *   6. If modular_sum is enabled, XOR every N bits into one output bit to debias.
 *
 * Thread safety: SemaphoreHandle_t guards shared state; push/pop and queue
 *                operations are safe to call from different FreeRTOS tasks.
 */

static constexpr size_t   MAX_FIFO_BITS    = 1000;
static constexpr size_t   BITS_PER_PACKET  = 16;
static constexpr size_t   MAX_SEND_QUEUE   = 100;   ///< max unsent uint16 packets

struct EntropyPacket {
    uint16_t value;
    bool     sent;
};

class EntropyEngine {
public:
    EntropyEngine();
    ~EntropyEngine();

    /** Feed a new C_now value from the BLE poll. Extracts an entropy bit. */
    void feedCNow(int16_t c_now);

    // ── FIFO access (for web display) ──────────────────────────────────────

    /** Number of bits currently in the FIFO ring buffer. */
    size_t fifoSize() const;

    /** Copy up to `count` most-recent bits into `out` (0/1 values). Returns actual count. */
    size_t getFIFOBits(uint8_t* out, size_t count) const;

    /** Fraction of 1s in the FIFO (bias indicator, ideal = 0.5). */
    float  biasFraction() const;

    // ── Send queue ─────────────────────────────────────────────────────────

    /** Number of unsent packets waiting to be uploaded. */
    size_t pendingPackets() const;

    /**
     * Pop the oldest unsent packet.
     * Returns true and fills `pkt` if one is available.
     */
    bool popPacket(EntropyPacket& pkt);

    /** Mark a previously popped packet as sent (by its value + its position). */
    void markSent(size_t queueIdx);

    // ── Configuration ──────────────────────────────────────────────────────

    void  setModularSum(bool enabled, uint8_t bits = 2);
    bool  isModularSumEnabled() const { return m_modularSumEnabled; }
    uint8_t modularSumBits()    const { return m_modularSumBits;    }

    /** Total entropy bits collected since boot. */
    uint64_t totalBitsCollected() const { return m_totalBits; }

private:
    // Ring buffer for FIFO bits
    uint8_t  m_fifo[MAX_FIFO_BITS];
    size_t   m_fifoHead;     ///< write pointer (oldest position when full)
    size_t   m_fifoCount;    ///< number of valid entries

    // Packet assembly
    uint8_t  m_accumBits[BITS_PER_PACKET];
    size_t   m_accumCount;

    // Modular sum state
    uint8_t  m_rawBitsForXOR[4];
    size_t   m_rawXORCount;

    // Send queue
    EntropyPacket m_sendQueue[MAX_SEND_QUEUE];
    size_t        m_sendHead;   ///< oldest entry
    size_t        m_sendCount;

    // Config
    bool    m_modularSumEnabled;
    uint8_t m_modularSumBits;

    // Statistics
    int16_t  m_lastCNow;
    bool     m_hasLastCNow;
    uint64_t m_totalBits;

    // Mutex for thread safety
    SemaphoreHandle_t m_mutex;

    void pushFIFOBit(uint8_t bit);
    void accumulateBit(uint8_t bit);
    void enqueuePacket(uint16_t value);
};
