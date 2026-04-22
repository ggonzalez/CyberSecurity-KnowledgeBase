<?php
/**
 * QRNGabri Backend – PSK Authentication Helper
 *
 * Validates the Bearer token in the Authorization header.
 * Uses hash_equals() for constant-time comparison to prevent timing attacks.
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

/**
 * Validate the PSK token from the request.
 * Sends a 401 JSON response and exits if invalid.
 */
function requireAuth(): void {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if (empty($header)) {
        sendAuthError('Missing Authorization header');
    }

    // Accept "Bearer <token>" format
    if (strpos($header, 'Bearer ') !== 0) {
        sendAuthError('Malformed Authorization header');
    }

    $token = substr($header, 7);

    // Constant-time comparison to prevent timing side-channels
    if (!defined('API_PSK') || !hash_equals(API_PSK, $token)) {
        sendAuthError('Invalid PSK token');
    }
}

function sendAuthError(string $message): void {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Unauthorized', 'message' => $message]);
    exit;
}
