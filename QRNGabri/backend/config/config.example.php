<?php
/**
 * QRNGabri Backend – Configuration
 *
 * Copy this file to config.php and fill in your actual credentials.
 * NEVER commit config.php to version control.
 */

// ── Database ─────────────────────────────────────────────────────────────────
define('DB_HOST', 'localhost');
define('DB_PORT', 3306);
define('DB_NAME', 'qrngabri');
define('DB_USER', 'qrngabri_user');
define('DB_PASS', 'CHANGE_ME_DB_PASS');
define('DB_CHARSET', 'utf8mb4');

// ── Security ──────────────────────────────────────────────────────────────────
// Pre-shared key – must match the psk stored on the ESP32 device.
// Generate with: openssl rand -base64 32
define('API_PSK', 'REPLACE_WITH_32_CHAR_RANDOM_TOKEN');

// Number of 16-bit packets to accumulate before generating a backend random number
define('PACKETS_PER_RANDOM', 2);   // 2 × 16 bits = 32-bit random number

// ── CORS ──────────────────────────────────────────────────────────────────────
// Set to your dashboard domain in production, e.g. 'https://qrngabri.example.com'
define('CORS_ORIGIN', '*');

// ── Timezone ─────────────────────────────────────────────────────────────────
define('APP_TIMEZONE', 'UTC');
