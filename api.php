<?php
require_once 'config.php';
require_once 'functions.php';

header('Content-Type: application/json');

// Get authorization header
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (!preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
    http_response_code(401);
    echo json_encode(['error' => 'Missing or invalid authorization header']);
    exit();
}

$token = $matches[1];

// Validate JWT token
$parts = explode('.', $token);
if (count($parts) !== 3) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid token format']);
    exit();
}

$header = json_decode(base64_decode($parts[0]), true);
$payload = json_decode(base64_decode($parts[1]), true);
$signature = $parts[2];

// Verify signature
$expectedSignature = base64url_encode(hash_hmac('sha256', $parts[0] . '.' . $parts[1], JWT_SECRET, true));
if ($signature !== $expectedSignature) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid token signature']);
    exit();
}

// Check expiration
if ($payload['exp'] < time()) {
    http_response_code(401);
    echo json_encode(['error' => 'Token expired']);
    exit();
}

// Handle API endpoints
$path = $_SERVER['PATH_INFO'] ?? '';

switch ($path) {
    case '/user':
        // Return user information
        $user = getUserById($payload['sub']);
        if ($user) {
            echo json_encode([
                'id' => $user['id'],
                'email' => $user['email'],
                'name' => $user['name'],
                'nickname' => $user['nickname'],
                'profile_picture' => $user['profile_picture']
            ]);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'User not found']);
        }
        break;
        
    default:
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint not found']);
        break;
}
?> 