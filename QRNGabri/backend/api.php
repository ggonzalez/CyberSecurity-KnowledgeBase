<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/data.php';

$configCandidates = [
    __DIR__ . '/config.php',
    __DIR__ . '/config/config.php',
];

foreach ($configCandidates as $candidate) {
    if (is_file($candidate)) {
        require_once $candidate;
        break;
    }
}

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: ' . CORS_ORIGIN);
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Authorization, Content-Type');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$requestUri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$rawPath = rtrim($requestUri, '/') ?: '/';

// Accept only /api/<endpoint> forms in flat deployment.
if (preg_match('#/api/(push|ping|status|random|entropy)$#', $rawPath, $m)) {
    $path = '/' . $m[1];
} else {
    $path = $rawPath;
}

switch (true) {
    case $path === '/push' && $requestMethod === 'POST':
        requireAuth();
        handlePush();
        break;

    case $path === '/ping' && $requestMethod === 'POST':
        requireAuth();
        handlePing();
        break;

    case $path === '/status' && $requestMethod === 'GET':
        requireAuth();
        handleStatus();
        break;

    case $path === '/random' && $requestMethod === 'GET':
        handleRandom();
        break;

    case $path === '/entropy' && $requestMethod === 'GET':
        handleEntropy();
        break;

    default:
        http_response_code(404);
        echo json_encode(['error' => 'Not Found', 'path' => $path]);
        break;
}