<?php
/**
 * QRNGabri Backend – Database Connection Helper
 */

$configCandidates = [
    __DIR__ . '/../config/config.php',
    __DIR__ . '/config.php',
];

foreach ($configCandidates as $candidate) {
    if (is_file($candidate)) {
        require_once $candidate;
        break;
    }
}

function getDB(): PDO {
    static $pdo = null;
    if ($pdo !== null) return $pdo;

    $dsn = sprintf(
        'mysql:host=%s;port=%d;dbname=%s;charset=%s',
        DB_HOST, DB_PORT, DB_NAME, DB_CHARSET
    );

    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];

    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    ensureSchema($pdo);
    return $pdo;
}

function ensureSchema(PDO $pdo): void {
    static $schemaReady = false;
    if ($schemaReady) {
        return;
    }

    $schemaSql = [
        "CREATE TABLE IF NOT EXISTS entropy_samples (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            device_id VARCHAR(64) NOT NULL,
            sample_value SMALLINT UNSIGNED NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_device_time (device_id, created_at),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS entropy_counter_samples (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            device_id VARCHAR(64) NOT NULL,
            counter_value TINYINT UNSIGNED NOT NULL,
            source_entropy_sample_id BIGINT UNSIGNED NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_counter_device_time (device_id, created_at),
            INDEX idx_counter_created_at (created_at),
            INDEX idx_counter_source (source_entropy_sample_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS generated_numbers (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            device_id VARCHAR(64) NOT NULL,
            random_value BIGINT UNSIGNED NOT NULL,
            bit_count TINYINT UNSIGNED NOT NULL DEFAULT 32,
            entropy_ids TEXT NOT NULL,
            generated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_device_gen (device_id, generated_at),
            INDEX idx_generated_at (generated_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        "CREATE TABLE IF NOT EXISTS device_status (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            device_id VARCHAR(64) NOT NULL UNIQUE,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            bits_collected BIGINT UNSIGNED NOT NULL DEFAULT 0,
            bias_score FLOAT NOT NULL DEFAULT 0.0,
            modular_sum_enabled TINYINT(1) NOT NULL DEFAULT 0,
            modular_sum_bits TINYINT NOT NULL DEFAULT 2,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_device (device_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    ];

    foreach ($schemaSql as $statement) {
        $pdo->exec($statement);
    }

    $schemaReady = true;
}
