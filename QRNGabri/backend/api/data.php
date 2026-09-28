<?php
/**
 * QRNGabri Backend – Data Endpoint Handlers
 *
 * Handlers for:
 *   POST /api/push    – receive entropy packets from device
 *   POST /api/counter – receive batches of accepted C_last values
 *   POST /api/ping    – connectivity/auth test with mock payload
 *   GET  /api/status  – device health summary
 *   GET  /api/random  – latest generated random number + history
 *   GET  /api/entropy – entropy sample history (with optional date range)
 *   GET  /api/samples – packet or C_last values for the dispersion plot
 *   GET  /api/raw-bits – unpacked raw bit stream with paired C-pulse bytes
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
// POST /api/counter
// Body (JSON):
// {
//   "device_id": "AA:BB:CC:DD:EE:FF",
//   "samples": [ { "c_last": 1234, "age_ms": 5000 }, ... ]
// }
// age_ms is how long ago the device accepted the reading; the row is back-dated
// by that amount so queued/retried samples keep their real acquisition time.
// ─────────────────────────────────────────────────────────────────────────────
const COUNTER_BATCH_MAX = 64;
const COUNTER_MAX_AGE_MS = 7 * 24 * 3600 * 1000;

function handleCounterPush(): void {
    $body = file_get_contents('php://input');
    $data = json_decode($body, true);

    if (!is_array($data)) {
        jsonError(400, 'Invalid JSON body');
    }

    $deviceId = trim((string)($data['device_id'] ?? ''));
    if (!preg_match('/^[0-9A-Fa-f:]{11,17}$/', $deviceId)) {
        jsonError(400, 'Invalid device_id format');
    }

    $samples = $data['samples'] ?? null;
    if (!is_array($samples) || count($samples) === 0 || array_keys($samples) !== range(0, count($samples) - 1)) {
        jsonError(400, 'samples must be a non-empty array');
    }
    if (count($samples) > COUNTER_BATCH_MAX) {
        jsonError(400, 'samples exceeds maximum length of ' . COUNTER_BATCH_MAX);
    }

    $rows = [];
    foreach ($samples as $i => $sample) {
        if (!is_array($sample)) {
            jsonError(400, 'samples[' . $i . '] must be an object');
        }
        $cLast = $sample['c_last'] ?? null;
        if (!is_int($cLast) || $cLast < 0 || $cLast > 65535) {
            jsonError(400, 'samples[' . $i . '].c_last must be an integer in [0, 65535]');
        }
        $ageMs = $sample['age_ms'] ?? 0;
        if (!is_int($ageMs) || $ageMs < 0 || $ageMs > COUNTER_MAX_AGE_MS) {
            jsonError(400, 'samples[' . $i . '].age_ms must be an integer in [0, ' . COUNTER_MAX_AGE_MS . ']');
        }
        $rows[] = [$cLast, intdiv($ageMs, 1000)];
    }

    $db = getDB();
    $stmt = $db->prepare(
        'INSERT INTO entropy_counter_samples (device_id, counter_value, c_last_value, created_at)
          VALUES (?, ?, ?, NOW() - INTERVAL ? SECOND)'
    );

    $db->beginTransaction();
    foreach ($rows as [$cLast, $ageSeconds]) {
        $stmt->execute([$deviceId, $cLast & 0xFF, $cLast, $ageSeconds]);
    }
    $db->commit();

    jsonOk(['status' => 'ok', 'stored' => count($rows)], 201);
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
    $readingBits = min(8, max(1, (int)($_GET['reading_bits'] ?? 1)));
    ['device_id' => $deviceId, 'from' => $from, 'to' => $to,
     'where' => $where, 'params' => $params] = parseRangeFilters();

    $db = getDB();

    $sourceTable = $readingBits === 1 ? 'entropy_samples' : 'entropy_counter_samples';
    $valueColumn = $readingBits === 1 ? 'sample_value' : 'counter_value';

    // ── Range-filtered display samples (scatter chart / sample list) ─────────
    $sql = "SELECT id, device_id, {$valueColumn} AS sample_value, created_at FROM {$sourceTable}";
    if ($where) $sql .= ' WHERE ' . implode(' AND ', $where);
    $sql .= ' ORDER BY created_at DESC, id DESC LIMIT ?';

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge($params, [$limit]));
    $displayRows = $stmt->fetchAll();

    $countSql = "SELECT COUNT(*) FROM {$sourceTable}";
    if ($where) $countSql .= ' WHERE ' . implode(' AND ', $where);
    $stmt = $db->prepare($countSql);
    $stmt->execute($params);
    $rangeCount = (int)$stmt->fetchColumn();

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
    $biasSql .= ' ORDER BY created_at ASC, id ASC';

    $stmt = $db->prepare($biasSql);
    $stmt->execute($biasParams);

    $modularSumBits = getDeviceModularSumBits($db, $deviceId);

    // Compute bias over the full history. Series points are only emitted for
    // rows inside the selected range, thinned to at most BIAS_SERIES_MAX_POINTS
    // so the payload stays small as the C_last log grows.
    $fromTs = $from ? $from . ' 00:00:00' : null;
    $toTs   = $to   ? $to   . ' 23:59:59' : null;
    $stride = max(1, (int)ceil($rangeCount / BIAS_SERIES_MAX_POINTS));
    $sampleBitWidth = $readingBits === 1 ? 16 : $readingBits;
    $measurements = 0;
    $rangeIndex = 0;
    $pendingPoint = null;   // last in-range point, kept so the series always ends on it

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

    while ($row = $stmt->fetch()) {
        $measurements++;
        $v = (int)$row['sample_value'];

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

        $createdAt = $row['created_at'];
        if (($fromTs !== null && $createdAt < $fromTs) || ($toTs !== null && $createdAt > $toTs)) {
            continue;
        }

        $pendingPoint = [
            'measurement' => $measurements,
            'value'       => $v,
            'created_at'  => $createdAt,
            'raw'         => $totalRawBits > 0 ? abs($totalRawOnes / $totalRawBits - 0.5) : 0.0,
            'corrected'   => $corrBits > 0 ? abs($corrOnes / $corrBits - 0.5) : 0.0,
            'von_neumann' => $vnBits > 0 ? abs($vnOnes / $vnBits - 0.5) : 0.0,
        ];
        if ($rangeIndex++ % $stride === 0) {
            appendBiasPoint($pendingPoint, $rawSeries, $correctedSeries, $vonNeumannSeries);
            $pendingPoint = null;
        }
    }
    if ($pendingPoint !== null) {
        appendBiasPoint($pendingPoint, $rawSeries, $correctedSeries, $vonNeumannSeries);
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
            'measurements'         => $measurements,
            'range_measurements'   => $rangeCount,
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
// GET /api/samples?source=packets|clast&from=YYYY-MM-DD&to=YYYY-MM-DD&device_id=...&limit=2000
// Values for the dispersion scatter: 16-bit packets (entropy_samples) or actual
// C_last values (entropy_counter_samples). Omit from/to for lifetime. When the
// range holds more than `limit` rows they are thinned evenly across it.
// Legacy counter rows have no c_last_value; their low-8-bit counter_value is
// used instead (equal to C_last whenever C_last < 256).
// ─────────────────────────────────────────────────────────────────────────────
function handleSamples(): void {
    $source = $_GET['source'] ?? 'packets';
    if (!in_array($source, ['packets', 'clast'], true)) {
        jsonError(400, 'source must be packets or clast');
    }
    $limit = min(5000, max(1, (int)($_GET['limit'] ?? 2000)));
    ['where' => $where, 'params' => $params] = parseRangeFilters();

    $table     = $source === 'packets' ? 'entropy_samples' : 'entropy_counter_samples';
    $valueExpr = $source === 'packets' ? 'sample_value' : 'COALESCE(c_last_value, counter_value)';
    $whereSql  = $where ? ' WHERE ' . implode(' AND ', $where) : '';

    $db = getDB();
    $stmt = $db->prepare("SELECT COUNT(*) FROM {$table}{$whereSql}");
    $stmt->execute($params);
    $total  = (int)$stmt->fetchColumn();
    $stride = max(1, (int)ceil($total / $limit));

    $stmt = $db->prepare(
        "SELECT id, {$valueExpr} AS value, created_at FROM {$table}{$whereSql} ORDER BY created_at ASC, id ASC"
    );
    $stmt->execute($params);

    $samples = [];
    $last = null;
    for ($i = 0; $row = $stmt->fetch(); $i++) {
        $row['value'] = (int)$row['value'];
        if ($i % $stride === 0) {
            $samples[] = $row;
            $last = null;
        } else {
            $last = $row;   // keep the newest row so the plot always ends at "now"
        }
    }
    if ($last !== null) {
        $samples[] = $last;
    }

    jsonOk([
        'source'  => $source,
        'total'   => $total,
        'stride'  => $stride,
        'samples' => $samples,
    ]);
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/raw-bits?device_id=...&after_id=0&limit=1000
// Returns one row per unpacked raw bit, preserving the original acquisition
// order inside each stored 16-bit packet.
// ─────────────────────────────────────────────────────────────────────────────
function handleRawBits(): void {
    $limit    = min(5000, max(1, (int)($_GET['limit'] ?? 1000)));
    $afterId  = max(0, (int)($_GET['after_id'] ?? 0));
    $deviceId = $_GET['device_id'] ?? null;

    if ($deviceId !== null && !preg_match('/^[0-9A-Fa-f:]{11,17}$/', $deviceId)) {
        jsonError(400, 'Invalid device_id');
    }

    $db = getDB();

    $where = ['s.id > ?'];
    $params = [$afterId];

    if ($deviceId) {
        $where[] = 's.device_id = ?';
        $params[] = $deviceId;
    }

    $sql = 'SELECT s.id, s.device_id, s.sample_value, s.created_at, c.counter_value
            FROM entropy_samples s
            LEFT JOIN entropy_counter_samples c
              ON c.source_entropy_sample_id = s.id
            WHERE ' . implode(' AND ', $where) . '
            ORDER BY s.id ASC
            LIMIT ?';
    $params[] = $limit;

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    $entries = [];
    $lastSampleId = null;
    foreach ($rows as $row) {
        $lastSampleId = (int)$row['id'];
        $entries[] = [
            'bit'  => (int)$row['sample_value'] & 0xFFFF,
            'byte' => $row['counter_value'] !== null ? (int)$row['counter_value'] : null,
        ];
    }

    jsonOk([
        'bits' => $entries,
        'meta' => [
            'device_id'       => $deviceId,
            'after_id'        => $afterId,
            'last_sample_id'  => $lastSampleId,
            'packets_returned'=> count($rows),
            'bits_returned'   => count($entries),
            'next_after_id'   => count($rows) === $limit ? $lastSampleId : null,
        ],
    ]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

const BIAS_SERIES_MAX_POINTS = 2000;

/**
 * Validate the optional device_id / from / to query parameters and build the
 * matching WHERE clauses. Missing from/to means no date bound (lifetime).
 */
function parseRangeFilters(): array {
    $deviceId = $_GET['device_id'] ?? null;
    $from     = $_GET['from'] ?? null;
    $to       = $_GET['to']   ?? null;

    if ($deviceId !== null && !preg_match('/^[0-9A-Fa-f:]{11,17}$/', $deviceId)) {
        jsonError(400, 'Invalid device_id');
    }
    if ($from !== null && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) {
        jsonError(400, 'Invalid from date format (YYYY-MM-DD)');
    }
    if ($to !== null && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $to)) {
        jsonError(400, 'Invalid to date format (YYYY-MM-DD)');
    }

    $where  = [];
    $params = [];
    if ($deviceId) { $where[] = 'device_id = ?';   $params[] = $deviceId; }
    if ($from)     { $where[] = 'created_at >= ?'; $params[] = $from . ' 00:00:00'; }
    if ($to)       { $where[] = 'created_at <= ?'; $params[] = $to   . ' 23:59:59'; }

    return ['device_id' => $deviceId, 'from' => $from, 'to' => $to,
            'where' => $where, 'params' => $params];
}

function appendBiasPoint(array $point, array &$raw, array &$corrected, array &$vonNeumann): void {
    $base = [
        'measurement' => $point['measurement'],
        'value'       => $point['value'],
        'created_at'  => $point['created_at'],
    ];
    $raw[]        = $base + ['bias' => round($point['raw'], 6)];
    $corrected[]  = $base + ['bias' => round($point['corrected'], 6)];
    $vonNeumann[] = $base + ['bias' => round($point['von_neumann'], 6)];
}

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
