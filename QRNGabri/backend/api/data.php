<?php
/**
 * QRNGabri Backend – Data Endpoint Handlers
 *
 * Handlers for:
 *   POST /api/push    – receive entropy packets from device
 *   POST /api/ping    – connectivity/auth test with mock payload
 *   GET  /api/status  – device health summary
 *   GET  /api/random  – latest generated random number + history
 *   GET  /api/entropy – entropy sample history (with optional date range)
 */

require_once __DIR__ . '/db.php';

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

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/push
// Body (JSON): { "device_id": "AA:BB:CC:DD:EE:FF", "value": 12345 }
// ─────────────────────────────────────────────────────────────────────────────
function handlePush(): void {
    $body = file_get_contents('php://input');
    $data = json_decode($body, true);

    if (!is_array($data)) {
        jsonError(400, 'Invalid JSON body');
    }

    // Input validation
    $deviceId = trim($data['device_id'] ?? '');
    if (!preg_match('/^[0-9A-Fa-f:]{11,17}$/', $deviceId)) {
        jsonError(400, 'Invalid device_id format');
    }

    $valueRaw = $data['value'] ?? null;
    if (!is_int($valueRaw) && !ctype_digit((string)$valueRaw)) {
        jsonError(400, 'value must be a 16-bit unsigned integer');
    }
    $value = (int)$valueRaw;
    if ($value < 0 || $value > 65535) {
        jsonError(400, 'value out of range [0, 65535]');
    }

    $counter8 = null;
    if (array_key_exists('c_counter_8bit', $data) && $data['c_counter_8bit'] !== null) {
        $counterRaw = $data['c_counter_8bit'];
        if (!is_int($counterRaw) && !ctype_digit((string)$counterRaw)) {
            jsonError(400, 'c_counter_8bit must be an unsigned integer');
        }
        $counter8 = (int)$counterRaw;
        if ($counter8 < 0 || $counter8 > 255) {
            jsonError(400, 'c_counter_8bit out of range [0, 255]');
        }
    }

    $modularSum     = isset($data['modular_sum'])      ? (bool)$data['modular_sum']      : false;
    $modularSumBits = isset($data['modular_sum_bits']) ? (int)$data['modular_sum_bits']  : 2;

    $db = getDB();

    // Store entropy sample
    $stmt = $db->prepare(
        'INSERT INTO entropy_samples (device_id, sample_value) VALUES (?, ?)'
    );
    $stmt->execute([$deviceId, $value]);
    $sampleId = (int)$db->lastInsertId();

    if ($counter8 !== null) {
        $stmt = $db->prepare(
            'INSERT INTO entropy_counter_samples (device_id, counter_value, source_entropy_sample_id) VALUES (?, ?, ?)'
        );
        $stmt->execute([$deviceId, $counter8, $sampleId]);
    }

    // Upsert device status
    upsertDeviceStatus($db, $deviceId, $modularSum, $modularSumBits);

    // Check if we have enough packets to generate a random number
    $generatedNumber = maybeGenerateRandom($db, $deviceId);

    $response = ['status' => 'ok', 'sample_id' => $sampleId];
    if ($generatedNumber !== null) {
        // Return as hex string to avoid JS integer precision issues
        $response['random_number'] = formatRandomHex($generatedNumber, PACKETS_PER_RANDOM * 16);
    }

    jsonOk($response, 201);
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/ping
// Body (JSON):
// {
//   "device_id": "AA:BB:CC:DD:EE:FF",
//   "mock_values": [4660, 22136, 39612],
//   "note": "optional diagnostic string"
// }
// Auth required (Bearer PSK); does not write to DB.
// ─────────────────────────────────────────────────────────────────────────────
function handlePing(): void {
    $body = file_get_contents('php://input');
    $data = json_decode($body, true);

    if (!is_array($data)) {
        jsonError(400, 'Invalid JSON body');
    }

    $deviceId = trim((string)($data['device_id'] ?? ''));
    if ($deviceId === '') {
        $deviceId = 'unknown';
    } elseif (!preg_match('/^[0-9A-Fa-f:]{11,17}$/', $deviceId)) {
        jsonError(400, 'Invalid device_id format');
    }

    $mockValues = $data['mock_values'] ?? [];
    if (!is_array($mockValues)) {
        jsonError(400, 'mock_values must be an array');
    }
    if (count($mockValues) > 64) {
        jsonError(400, 'mock_values exceeds maximum length of 64');
    }

    foreach ($mockValues as $i => $valueRaw) {
        if (!is_int($valueRaw) && !ctype_digit((string)$valueRaw)) {
            jsonError(400, 'mock_values[' . $i . '] must be a 16-bit unsigned integer');
        }
        $value = (int)$valueRaw;
        if ($value < 0 || $value > 65535) {
            jsonError(400, 'mock_values[' . $i . '] out of range [0, 65535]');
        }
    }

    $note = '';
    if (isset($data['note'])) {
        $note = substr(trim((string)$data['note']), 0, 160);
    }

    jsonOk([
        'status' => 'ok',
        'auth' => 'ok',
        'endpoint' => 'ping',
        'device_id' => $deviceId,
        'received_mock_values' => count($mockValues),
        'server_time_utc' => gmdate('c'),
        'echo' => [
            'note' => $note,
            'mock_values' => $mockValues,
        ],
    ]);
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/status?device_id=AA:BB:...
// ─────────────────────────────────────────────────────────────────────────────
function handleStatus(): void {
    $db = getDB();

    $deviceId = $_GET['device_id'] ?? null;

    if ($deviceId !== null) {
        if (!preg_match('/^[0-9A-Fa-f:]{11,17}$/', $deviceId)) {
            jsonError(400, 'Invalid device_id format');
        }
        $stmt = $db->prepare(
            'SELECT * FROM device_status WHERE device_id = ? LIMIT 1'
        );
        $stmt->execute([$deviceId]);
        $row = $stmt->fetch();
        jsonOk($row ?: (object)[]);
    }

    // All devices
    $rows = $db->query('SELECT * FROM device_status ORDER BY last_seen DESC')->fetchAll();
    jsonOk($rows);
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/random?limit=20&device_id=...
// ─────────────────────────────────────────────────────────────────────────────
function handleRandom(): void {
    $limit    = min(100, max(1, (int)($_GET['limit'] ?? 20)));
    $deviceId = $_GET['device_id'] ?? null;
    $db = getDB();

    if ($deviceId !== null && !preg_match('/^[0-9A-Fa-f:]{11,17}$/', $deviceId)) {
        jsonError(400, 'Invalid device_id');
    }

    $sql    = 'SELECT * FROM generated_numbers';
    $params = [];
    if ($deviceId) {
        $sql .= ' WHERE device_id = ?';
        $params[] = $deviceId;
    }
    $sql .= ' ORDER BY generated_at DESC LIMIT ?';
    $params[] = $limit;

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    // Format random_value as hex for precision-safe transmission
    foreach ($rows as &$row) {
        $row['random_hex'] = formatRandomHex((int)$row['random_value'], (int)$row['bit_count']);
    }

    jsonOk($rows);
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/entropy?from=YYYY-MM-DD&to=YYYY-MM-DD&device_id=...&limit=500
// ─────────────────────────────────────────────────────────────────────────────
function handleEntropy(): void {
    $limit    = min(5000, max(1, (int)($_GET['limit'] ?? 500)));
    $deviceId = $_GET['device_id'] ?? null;
    $from     = $_GET['from'] ?? null;
    $to       = $_GET['to']   ?? null;
    $readingBits = min(8, max(1, (int)($_GET['reading_bits'] ?? 1)));

    if ($deviceId !== null && !preg_match('/^[0-9A-Fa-f:]{11,17}$/', $deviceId)) {
        jsonError(400, 'Invalid device_id');
    }
    if ($from !== null && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) {
        jsonError(400, 'Invalid from date format (YYYY-MM-DD)');
    }
    if ($to !== null && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $to)) {
        jsonError(400, 'Invalid to date format (YYYY-MM-DD)');
    }

    $db = getDB();

    $sourceTable = $readingBits === 1 ? 'entropy_samples' : 'entropy_counter_samples';
    $valueColumn = $readingBits === 1 ? 'sample_value' : 'counter_value';

    // ── Range-filtered display samples (scatter chart / sample list) ─────────
    $where  = [];
    $params = [];
    if ($deviceId) { $where[] = 'device_id = ?'; $params[] = $deviceId; }
    if ($from)     { $where[] = 'created_at >= ?'; $params[] = $from . ' 00:00:00'; }
    if ($to)       { $where[] = 'created_at <= ?'; $params[] = $to   . ' 23:59:59'; }

    $sql = "SELECT id, device_id, {$valueColumn} AS sample_value, created_at FROM {$sourceTable}";
    if ($where) $sql .= ' WHERE ' . implode(' AND ', $where);
    $sql .= ' ORDER BY created_at DESC LIMIT ?';
    $params[] = $limit;

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $displayRows = $stmt->fetchAll();

    // Mask display values to selected bit width for scatter chart
    if ($readingBits > 1) {
        $mask = (1 << $readingBits) - 1;
        foreach ($displayRows as &$row) {
            $row['sample_value'] = (int)$row['sample_value'] & $mask;
        }
        unset($row);
    }

    // ── Full-history samples for bias computation (no date filter) ───────────
    $biasWhere  = [];
    $biasParams = [];
    if ($deviceId) { $biasWhere[] = 'device_id = ?'; $biasParams[] = $deviceId; }

    $biasSql = "SELECT {$valueColumn} AS sample_value, created_at FROM {$sourceTable}";
    if ($biasWhere) $biasSql .= ' WHERE ' . implode(' AND ', $biasWhere);
    $biasSql .= ' ORDER BY created_at ASC LIMIT 5000';

    $stmt = $db->prepare($biasSql);
    $stmt->execute($biasParams);
    $allRows = $stmt->fetchAll();

    $modularSumBits = getDeviceModularSumBits($db, $deviceId);

    // Compute bias series over the full history
    $totalRawOnes = 0;
    $totalRawBits = 0;
    $rawSeries = [];
    $correctedSeries = [];
    $vonNeumannSeries = [];
    $corrAccum = [];
    $corrOnes = 0;
    $corrBits = 0;
    $vnAccum = [];
    $vnOnes = 0;
    $vnBits = 0;

    foreach ($allRows as $index => $row) {
        $v = (int)$row['sample_value'];
        $sampleBitWidth = $readingBits === 1 ? 16 : $readingBits;

        for ($b = 0; $b < $sampleBitWidth; $b++) {
            $bit = ($v >> $b) & 0x01;
            $totalRawOnes += $bit;
            $totalRawBits++;

            $corrAccum[] = $bit;
            if (count($corrAccum) >= $modularSumBits) {
                $x = 0;
                foreach ($corrAccum as $rb) { $x ^= $rb; }
                $corrOnes += $x;
                $corrBits++;
                $corrAccum = [];
            }

            // Von Neumann: accumulate pairs, discard matching pairs, keep 01→0 and 10→1
            $vnAccum[] = $bit;
            if (count($vnAccum) >= 2) {
                $pair = ($vnAccum[0] << 1) | $vnAccum[1];
                if ($pair === 1 || $pair === 2) { // 01 or 10
                    $vnOnes += ($pair === 2 ? 1 : 0); // 10 → 1, 01 → 0
                    $vnBits++;
                }
                // 00 and 11 are discarded
                $vnAccum = [];
            }
        }

        $rawBias  = $totalRawBits > 0 ? abs($totalRawOnes / $totalRawBits - 0.5) : 0.0;
        $corrBias = $corrBits > 0 ? abs($corrOnes / $corrBits - 0.5) : 0.0;
        $vnBias   = $vnBits > 0 ? abs($vnOnes / $vnBits - 0.5) : 0.0;

        $rawSeries[] = [
            'measurement' => $index + 1,
            'bias'        => round($rawBias, 6),
            'value'       => $v,
            'created_at'  => $row['created_at'],
        ];
        $correctedSeries[] = [
            'measurement' => $index + 1,
            'bias'        => round($corrBias, 6),
            'value'       => $v,
            'created_at'  => $row['created_at'],
        ];
        $vonNeumannSeries[] = [
            'measurement' => $index + 1,
            'bias'        => round($vnBias, 6),
            'value'       => $v,
            'created_at'  => $row['created_at'],
        ];
    }

    $rawZeros = max(0, $totalRawBits - $totalRawOnes);
    $rawBias  = $totalRawBits > 0 ? abs($totalRawOnes / $totalRawBits - 0.5) : 0.0;
    $corrBias = $corrBits > 0 ? abs($corrOnes / $corrBits - 0.5) : 0.0;
    $vnBias   = $vnBits > 0 ? abs($vnOnes / $vnBits - 0.5) : 0.0;

    jsonOk([
        'samples'              => $displayRows,
        'bias_series'          => $rawSeries,
        'bias_series_raw'      => $rawSeries,
        'bias_series_corrected'=> $correctedSeries,
        'bias_series_von_neumann' => $vonNeumannSeries,
        'stats' => [
            'reading_bits'         => $readingBits,
            'ones'                 => $totalRawOnes,
            'zeros'                => $rawZeros,
            'total'                => $totalRawBits,
            'measurements'         => count($allRows),
            'range_measurements'   => count($displayRows),
            'bias'                 => round($rawBias, 6),
            'raw_bias'             => round($rawBias, 6),
            'corrected_bias'       => round($corrBias, 6),
            'von_neumann_bias'     => round($vnBias, 6),
            'modular_sum_bits'     => $modularSumBits,
            'corrected_total_bits' => $corrBits,
            'von_neumann_total_bits' => $vnBits,
        ],
    ]);
}





// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

function upsertDeviceStatus(PDO $db, string $deviceId,
                            bool $modSum, int $modSumBits): void {
    // Compute bias from last 1000 samples
    $stmt = $db->prepare(
        'SELECT sample_value FROM entropy_samples
          WHERE device_id = ?
          ORDER BY created_at DESC
          LIMIT 1000'
    );
    $stmt->execute([$deviceId]);
    $samples = $stmt->fetchAll(PDO::FETCH_COLUMN);

    $ones = 0; $total = 0;
    foreach ($samples as $v) {
        $v = (int)$v;
        for ($b = 0; $b < 16; $b++) {
            if ($v & (1 << $b)) $ones++;
            $total++;
        }
    }
    $bias = $total > 0 ? abs($ones / $total - 0.5) : 0.0;

    $stmt = $db->prepare(
        'INSERT INTO device_status
            (device_id, last_seen, bits_collected, bias_score, modular_sum_enabled, modular_sum_bits)
          VALUES (?, NOW(), ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            last_seen           = NOW(),
            bits_collected      = bits_collected + VALUES(bits_collected),
            bias_score          = VALUES(bias_score),
            modular_sum_enabled = VALUES(modular_sum_enabled),
            modular_sum_bits    = VALUES(modular_sum_bits)'
    );
    $stmt->execute([$deviceId, 16, round($bias, 6), (int)$modSum, $modSumBits]);
}

function getDeviceModularSumBits(PDO $db, ?string $deviceId): int {
    $fallback = 2;
    $bits = $fallback;

    if ($deviceId !== null && $deviceId !== '') {
        $stmt = $db->prepare('SELECT modular_sum_bits FROM device_status WHERE device_id = ? LIMIT 1');
        $stmt->execute([$deviceId]);
        $row = $stmt->fetch();
        if ($row && isset($row['modular_sum_bits'])) {
            $bits = (int)$row['modular_sum_bits'];
        }
    } else {
        $row = $db->query('SELECT modular_sum_bits FROM device_status ORDER BY last_seen DESC LIMIT 1')->fetch();
        if ($row && isset($row['modular_sum_bits'])) {
            $bits = (int)$row['modular_sum_bits'];
        }
    }

    if ($bits < 2 || $bits > 8) {
        return $fallback;
    }
    return $bits;
}

/**
 * Check if we have enough pending (unused) entropy samples to generate a new
 * random number. If so, generate it and persist it.
 *
 * Returns the generated random number as an integer, or null if not enough
 * source packets are available yet.
 */
function maybeGenerateRandom(PDO $db, string $deviceId): ?int {
    // Find entropy_samples not yet used in a generated_number for this device
    // We track usage via a simple subquery against generated_numbers.entropy_ids
    // For scalability, a used_in_random column would be better, but this is fine
    // for moderate workloads.
    $stmt = $db->prepare(
        'SELECT id, sample_value FROM entropy_samples
          WHERE device_id = ?
            AND id NOT IN (
              SELECT CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(entropy_ids, \',\', n.n), \',\', -1) AS UNSIGNED)
              FROM generated_numbers gn
              JOIN (SELECT 1 n UNION SELECT 2 UNION SELECT 3 UNION SELECT 4) n
                ON CHAR_LENGTH(entropy_ids) - CHAR_LENGTH(REPLACE(entropy_ids, \',\', \'\')) >= n.n - 1
              WHERE gn.device_id = ?
            )
          ORDER BY id ASC
          LIMIT ?'
    );
    $needed = PACKETS_PER_RANDOM;
    $stmt->execute([$deviceId, $deviceId, $needed]);
    $samples = $stmt->fetchAll();

    if (count($samples) < $needed) {
        return null;
    }

    // Assemble PACKETS_PER_RANDOM × 16 bits into one backend random value.
    $randomValue = 0;
    $ids         = [];
    foreach ($samples as $i => $s) {
        $randomValue |= ((int)$s['sample_value'] & 0xFFFF) << ($i * 16);
        $ids[]        = (int)$s['id'];
    }

    $idList = implode(',', $ids);
    $stmt = $db->prepare(
        'INSERT INTO generated_numbers (device_id, random_value, bit_count, entropy_ids)
          VALUES (?, ?, ?, ?)'
    );
    $stmt->execute([$deviceId, $randomValue, $needed * 16, $idList]);

    return $randomValue;
}

function formatRandomHex(int $value, int $bitCount): string {
    $hexDigits = max(1, (int)ceil($bitCount / 4));
    return sprintf('0x%0' . $hexDigits . 'X', $value);
}

function jsonOk($data, int $code = 200): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function jsonError(int $code, string $message): void {
    http_response_code($code);
    echo json_encode(['error' => $message]);
    exit;
}
