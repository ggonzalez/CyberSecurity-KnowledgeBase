-- QRNGabri Database Schema
-- MySQL / MariaDB
-- Run: mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS qrngabri
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE qrngabri;

-- ── entropy_samples ──────────────────────────────────────────────────────────
-- Stores each 16-bit entropy packet pushed by the device.
CREATE TABLE IF NOT EXISTS entropy_samples (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id    VARCHAR(64)      NOT NULL,
    sample_value SMALLINT UNSIGNED NOT NULL,   -- 16-bit raw entropy packet
    created_at   DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_device_time (device_id, created_at),
    INDEX idx_created_at  (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── entropy_counter_samples ────────────────────────────────────────────────
-- Stores per-upload 8-bit counter snapshots from the device for extra analysis.
CREATE TABLE IF NOT EXISTS entropy_counter_samples (
    id                      BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id               VARCHAR(64)      NOT NULL,
    counter_value           TINYINT UNSIGNED NOT NULL,   -- low 8 bits of C counter
    source_entropy_sample_id BIGINT UNSIGNED NULL,       -- linked entropy_samples.id when available
    created_at              DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_counter_device_time (device_id, created_at),
    INDEX idx_counter_created_at  (created_at),
    INDEX idx_counter_source      (source_entropy_sample_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── generated_numbers ────────────────────────────────────────────────────────
-- Each row is a 32-bit random number assembled from PACKETS_PER_RANDOM packets.
CREATE TABLE IF NOT EXISTS generated_numbers (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id       VARCHAR(64)      NOT NULL,
    random_value    BIGINT UNSIGNED  NOT NULL,   -- 32-bit random number stored in an integer column
    bit_count       TINYINT UNSIGNED NOT NULL DEFAULT 32,
    entropy_ids     TEXT             NOT NULL,   -- comma-separated entropy_sample IDs used
    generated_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_device_gen (device_id, generated_at),
    INDEX idx_generated_at (generated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── device_status ────────────────────────────────────────────────────────────
-- Tracks per-device health metrics.
CREATE TABLE IF NOT EXISTS device_status (
    id                    INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id             VARCHAR(64)  NOT NULL UNIQUE,
    last_seen             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    bits_collected        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bias_score            FLOAT        NOT NULL DEFAULT 0.0,
    modular_sum_enabled   TINYINT(1)   NOT NULL DEFAULT 0,
    modular_sum_bits      TINYINT      NOT NULL DEFAULT 2,
    updated_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                       ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_device (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
