<?php
/**
 * QRNGabri Backend – REST API Router
 *
 * Routes:
 *   POST /api/push     – receive entropy packet from device  [requires PSK auth]
 *   POST /api/ping     – connectivity/auth check with mock payload [requires PSK auth]
 *   GET  /api/status   – device health                       [requires PSK auth]
 *   GET  /api/random   – generated random numbers            [no auth – public read]
 *   GET  /api/entropy  – entropy history with bias stats     [no auth – public read]
 */

// ── Bootstrap ────────────────────────────────────────────────────────────────
date_default_timezone_set('UTC');

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

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/data.php';

// ── CORS headers ─────────────────────────────────────────────────────────────
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: ' . CORS_ORIGIN);
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Authorization, Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ── Route parsing ─────────────────────────────────────────────────────────────
$requestUri    = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$requestMethod = $_SERVER['REQUEST_METHOD'];

// Strip /api prefix if present (depends on server config / .htaccess)
$path = preg_replace('#^/api#', '', $requestUri);
$path = rtrim($path, '/') ?: '/';

// ── Dispatch ──────────────────────────────────────────────────────────────────
switch (true) {
    // POST /push – authenticated, device writes entropy
    case $path === '/push' && $requestMethod === 'POST':
        requireAuth();
        handlePush();
        break;

    // POST /ping – authenticated connectivity check
    case $path === '/ping' && $requestMethod === 'POST':
        requireAuth();
        handlePing();
        break;

    // GET /status – authenticated
    case $path === '/status' && $requestMethod === 'GET':
        requireAuth();
        handleStatus();
        break;

    // GET /random – public read
    case $path === '/random' && $requestMethod === 'GET':
        handleRandom();
        break;

    // GET /entropy – public read
    case $path === '/entropy' && $requestMethod === 'GET':
        handleEntropy();
        break;

    default:
        http_response_code(404);
        echo json_encode(['error' => 'Not Found', 'path' => $path]);
        break;
}
