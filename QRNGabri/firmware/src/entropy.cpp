#include "entropy.h"
#include <string.h>

// ─── Constructor / Destructor ─────────────────────────────────────────────────
EntropyEngine::EntropyEngine()
    : m_fifoHead(0), m_fifoCount(0),
      m_accumCount(0), m_rawXORCount(0),
      m_sendHead(0), m_sendCount(0),
      m_modularSumEnabled(false), m_modularSumBits(2),
      m_lastCNow(0), m_hasLastCNow(false), m_totalBits(0)
{
    memset(m_fifo,          0, sizeof(m_fifo));
    memset(m_accumBits,     0, sizeof(m_accumBits));
    memset(m_rawBitsForXOR, 0, sizeof(m_rawBitsForXOR));
    memset(m_sendQueue,     0, sizeof(m_sendQueue));
    m_mutex = xSemaphoreCreateMutex();
}

EntropyEngine::~EntropyEngine() {
    if (m_mutex) vSemaphoreDelete(m_mutex);
}

// ─── Configuration ────────────────────────────────────────────────────────────
void EntropyEngine::setModularSum(bool enabled, uint8_t bits) {
    xSemaphoreTake(m_mutex, portMAX_DELAY);
    m_modularSumEnabled = enabled;
    m_modularSumBits    = (bits >= 2 && bits <= 4) ? bits : 2;
    // Reset accumulation state when config changes
    m_accumCount    = 0;
    m_rawXORCount   = 0;
    xSemaphoreGive(m_mutex);
}

// ─── Main entry point ─────────────────────────────────────────────────────────
void EntropyEngine::feedCNow(int16_t c_now) {
    xSemaphoreTake(m_mutex, portMAX_DELAY);

    if (!m_hasLastCNow) {
        m_lastCNow    = c_now;
        m_hasLastCNow = true;
        xSemaphoreGive(m_mutex);
        return;
    }

    // Delta: difference in pulse count between polls
    int16_t delta = c_now - m_lastCNow;
    m_lastCNow    = c_now;

    // LSB of delta is our raw entropy bit
    uint8_t rawBit = static_cast<uint8_t>(delta) & 0x01;
    m_totalBits++;

    if (m_modularSumEnabled) {
        // Accumulate N raw bits, XOR them to produce one debiased output bit
        m_rawBitsForXOR[m_rawXORCount++] = rawBit;
        if (m_rawXORCount >= m_modularSumBits) {
            uint8_t xored = 0;
            for (uint8_t i = 0; i < m_modularSumBits; i++) xored ^= m_rawBitsForXOR[i];
            m_rawXORCount = 0;
            pushFIFOBit(xored);
            accumulateBit(xored);
        }
    } else {
        pushFIFOBit(rawBit);
        accumulateBit(rawBit);
    }

    xSemaphoreGive(m_mutex);
}

// ─── FIFO ─────────────────────────────────────────────────────────────────────
void EntropyEngine::pushFIFOBit(uint8_t bit) {
    // Ring buffer: overwrite oldest when full
    size_t writePos = (m_fifoHead + m_fifoCount) % MAX_FIFO_BITS;
    m_fifo[writePos] = bit & 0x01;

    if (m_fifoCount < MAX_FIFO_BITS) {
        m_fifoCount++;
    } else {
        // Overwrite oldest — advance head
        m_fifoHead = (m_fifoHead + 1) % MAX_FIFO_BITS;
    }
}

size_t EntropyEngine::fifoSize() const {
    xSemaphoreTake(m_mutex, portMAX_DELAY);
    size_t sz = m_fifoCount;
    xSemaphoreGive(m_mutex);
    return sz;
}

size_t EntropyEngine::getFIFOBits(uint8_t* out, size_t count) const {
    xSemaphoreTake(m_mutex, portMAX_DELAY);
    size_t available = (count < m_fifoCount) ? count : m_fifoCount;
    // Copy from most recent downward
    for (size_t i = 0; i < available; i++) {
        size_t pos = (m_fifoHead + m_fifoCount - available + i) % MAX_FIFO_BITS;
        out[i] = m_fifo[pos];
    }
    xSemaphoreGive(m_mutex);
    return available;
}

float EntropyEngine::biasFraction() const {
    xSemaphoreTake(m_mutex, portMAX_DELAY);
    if (m_fifoCount == 0) {
        xSemaphoreGive(m_mutex);
        return 0.5f;
    }
    uint32_t ones = 0;
    for (size_t i = 0; i < m_fifoCount; i++) {
        size_t pos = (m_fifoHead + i) % MAX_FIFO_BITS;
        if (m_fifo[pos]) ones++;
    }
    float frac = static_cast<float>(ones) / static_cast<float>(m_fifoCount);
    xSemaphoreGive(m_mutex);
    return frac;
}

// ─── Packet assembly ──────────────────────────────────────────────────────────
void EntropyEngine::accumulateBit(uint8_t bit) {
    m_accumBits[m_accumCount++] = bit & 0x01;
    if (m_accumCount >= BITS_PER_PACKET) {
        uint16_t packet = 0;
        for (size_t i = 0; i < BITS_PER_PACKET; i++) {
            if (m_accumBits[i]) packet |= (1u << i);
        }
        enqueuePacket(packet);
        m_accumCount = 0;
    }
}

void EntropyEngine::enqueuePacket(uint16_t value) {
    if (m_sendCount >= MAX_SEND_QUEUE) {
        // Drop oldest unsent packet to make room (should rarely happen)
        m_sendHead  = (m_sendHead + 1) % MAX_SEND_QUEUE;
        m_sendCount--;
    }
    size_t insertPos = (m_sendHead + m_sendCount) % MAX_SEND_QUEUE;
    m_sendQueue[insertPos].value = value;
    m_sendQueue[insertPos].sent  = false;
    m_sendCount++;
}

// ─── Send queue ───────────────────────────────────────────────────────────────
size_t EntropyEngine::pendingPackets() const {
    xSemaphoreTake(m_mutex, portMAX_DELAY);
    size_t count = 0;
    for (size_t i = 0; i < m_sendCount; i++) {
        size_t pos = (m_sendHead + i) % MAX_SEND_QUEUE;
        if (!m_sendQueue[pos].sent) count++;
    }
    xSemaphoreGive(m_mutex);
    return count;
}

bool EntropyEngine::popPacket(EntropyPacket& pkt) {
    xSemaphoreTake(m_mutex, portMAX_DELAY);
    for (size_t i = 0; i < m_sendCount; i++) {
        size_t pos = (m_sendHead + i) % MAX_SEND_QUEUE;
        if (!m_sendQueue[pos].sent) {
            pkt = m_sendQueue[pos];
            m_sendQueue[pos].sent = true;   // mark as in-flight
            xSemaphoreGive(m_mutex);
            return true;
        }
    }
    xSemaphoreGive(m_mutex);
    return false;
}

void EntropyEngine::markSent(size_t queueIdx) {
    xSemaphoreTake(m_mutex, portMAX_DELAY);
    if (queueIdx < MAX_SEND_QUEUE) {
        m_sendQueue[queueIdx].sent = true;
    }
    // Compact: remove sent entries from the head of the queue
    while (m_sendCount > 0 && m_sendQueue[m_sendHead].sent) {
        m_sendHead  = (m_sendHead + 1) % MAX_SEND_QUEUE;
        m_sendCount--;
    }
    xSemaphoreGive(m_mutex);
}
