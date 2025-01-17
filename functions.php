<?php
require_once 'database.php';

function getUserById($id) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function getUserByEmail($email) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function createUser($email, $password, $name, $nickname = null) {
    $pdo = Database::connect();
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    
    // Generate @ayda.su email
    $aydaEmail = generateAydaEmail($name, $nickname);
    
    $stmt = $pdo->prepare("INSERT INTO users (email, password, name, nickname, created_at) VALUES (?, ?, ?, ?, NOW())");
    return $stmt->execute([$aydaEmail, $hashedPassword, $name, $nickname]);
}

function generateAydaEmail($name, $nickname = null) {
    $base = $nickname ? $nickname : $name;
    $base = strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $base));
    
    $pdo = Database::connect();
    $email = $base . '@' . EMAIL_DOMAIN;
    $counter = 1;
    
    while (getUserByEmail($email)) {
        $email = $base . $counter . '@' . EMAIL_DOMAIN;
        $counter++;
    }
    
    return $email;
}

function getUserApps($userId) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("SELECT * FROM apps WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->execute([$userId]);
    $apps = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Mark secrets as shown for apps that haven't been shown yet
    foreach ($apps as $app) {
        if (!$app['secret_shown']) {
            markSecretAsShown($app['id'], $userId);
        }
    }
    
    return $apps;
}

function getUserAuthorizedApps($userId) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("
        SELECT a.*, ua.authorized_at 
        FROM apps a 
        JOIN user_app_authorizations ua ON a.id = ua.app_id 
        WHERE ua.user_id = ? 
        ORDER BY ua.authorized_at DESC
    ");
    $stmt->execute([$userId]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function createApp($userId, $name, $description, $redirectUri) {
    $pdo = Database::connect();
    $clientId = generateClientId();
    $clientSecret = generateClientSecret();
    
    $stmt = $pdo->prepare("INSERT INTO apps (user_id, name, description, client_id, client_secret, redirect_uri, secret_shown, created_at) VALUES (?, ?, ?, ?, ?, ?, FALSE, NOW())");
    return $stmt->execute([$userId, $name, $description, $clientId, $clientSecret, $redirectUri]);
}

function generateClientId($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

function generateClientSecret($length = 64) {
    return bin2hex(random_bytes($length / 2));
}

function generateAuthorizationCode($length = 32) {
    return bin2hex(random_bytes($length / 2));
}

function createAuthorizationCode($userId, $appId) {
    $pdo = Database::connect();
    $code = generateAuthorizationCode();
    $expiresAt = date('Y-m-d H:i:s', time() + AUTH_CODE_EXPIRY);
    
    error_log("Creating authorization code - Expires at: $expiresAt");
    
    $stmt = $pdo->prepare("INSERT INTO authorization_codes (code, user_id, app_id, expires_at) VALUES (?, ?, ?, ?)");
    $stmt->execute([$code, $userId, $appId, $expiresAt]);
    
    return $code;
}

function validateAuthorizationCode($code) {
    error_log("Validating authorization code: $code");
    $pdo = Database::connect();
    $stmt = $pdo->prepare("SELECT * FROM authorization_codes WHERE code = ? AND used = FALSE AND expires_at > UTC_TIMESTAMP()");
    $stmt->execute([$code]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($result) {
        error_log("Found valid authorization code - Expires: {$result['expires_at']}, Used: {$result['used']}");
    } else {
        error_log("No valid authorization code found");
        // Check if code exists but is used or expired
        $stmt = $pdo->prepare("SELECT * FROM authorization_codes WHERE code = ?");
        $stmt->execute([$code]);
        $codeInfo = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($codeInfo) {
            error_log("Code exists but is " . ($codeInfo['used'] ? "already used" : "expired at {$codeInfo['expires_at']}"));
        }
    }
    
    return $result;
}

function markAuthorizationCodeUsed($code) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("UPDATE authorization_codes SET used = TRUE WHERE code = ?");
    return $stmt->execute([$code]);
}

function generateJWT($payload) {
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $payload = json_encode($payload);
    
    $headerEncoded = base64url_encode($header);
    $payloadEncoded = base64url_encode($payload);
    
    $signature = hash_hmac('sha256', $headerEncoded . '.' . $payloadEncoded, JWT_SECRET, true);
    $signatureEncoded = base64url_encode($signature);
    
    return $headerEncoded . '.' . $payloadEncoded . '.' . $signatureEncoded;
}

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function authorizeUserApp($userId, $appId) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("INSERT IGNORE INTO user_app_authorizations (user_id, app_id) VALUES (?, ?)");
    return $stmt->execute([$userId, $appId]);
}

function isAppAuthorized($userId, $appId) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("SELECT 1 FROM user_app_authorizations WHERE user_id = ? AND app_id = ?");
    $stmt->execute([$userId, $appId]);
    return $stmt->rowCount() > 0;
}

function markSecretAsShown($appId, $userId) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("UPDATE apps SET secret_shown = TRUE WHERE id = ? AND user_id = ?");
    return $stmt->execute([$appId, $userId]);
}

function updateUserProfilePicture($userId, $profilePictureUrl) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("UPDATE users SET profile_picture = ? WHERE id = ?");
    return $stmt->execute([$profilePictureUrl, $userId]);
}

function handleProfilePictureUpload($file) {
    $allowedTypes = ['image/jpeg', 'image/png'];
    $maxSize = 5 * 1024 * 1024; // 5MB
    
    if (!in_array($file['type'], $allowedTypes)) {
        throw new Exception('Invalid file type. Only JPG, PNG are allowed.');
    }
    
    if ($file['size'] > $maxSize) {
        throw new Exception('File is too large. Maximum size is 5MB.');
    }
    
    // Create image from file
    $sourceImage = $file['type'] === 'image/jpeg' 
        ? imagecreatefromjpeg($file['tmp_name'])
        : imagecreatefrompng($file['tmp_name']);
    
    if (!$sourceImage) {
        throw new Exception('Failed to process image.');
    }
    
    // Get original dimensions
    $width = imagesx($sourceImage);
    $height = imagesy($sourceImage);
    
    // Calculate square crop dimensions
    $size = min($width, $height);
    $x = floor(($width - $size) / 2);
    $y = floor(($height - $size) / 2);
    
    // Create new square image with white background
    $squareImage = imagecreatetruecolor(368, 368);
    $white = imagecolorallocate($squareImage, 255, 255, 255);
    imagefill($squareImage, 0, 0, $white);
    
    // Preserve transparency for PNG
    if ($file['type'] === 'image/png') {
        imagealphablending($squareImage, false);
        imagesavealpha($squareImage, true);
        $transparent = imagecolorallocatealpha($squareImage, 255, 255, 255, 127);
        imagefilledrectangle($squareImage, 0, 0, 368, 368, $transparent);
    }
    
    // Resize and crop
    if (!imagecopyresampled(
        $squareImage,
        $sourceImage,
        0, 0,           // Destination x, y
        $x, $y,         // Source x, y
        368, 368,       // Destination width, height
        $size, $size    // Source width, height
    )) {
        imagedestroy($sourceImage);
        imagedestroy($squareImage);
        throw new Exception('Failed to process image.');
    }
    
    // Generate filename and path
    $filename = uniqid() . '.webp';
    $uploadPath = 'uploads/profile_pictures/' . $filename;
    
    // Save as WebP with good quality
    $success = imagewebp($squareImage, $uploadPath, 80);
    
    // Clean up
    imagedestroy($sourceImage);
    imagedestroy($squareImage);
    
    if (!$success) {
        throw new Exception('Failed to save processed image.');
    }
    
    return $uploadPath;
}

function generateRefreshToken($userId, $appId) {
    $pdo = Database::connect();
    $token = bin2hex(random_bytes(32));
    $expiresAt = date('Y-m-d H:i:s', time() + (30 * 24 * 3600)); // 30 days
    
    $stmt = $pdo->prepare("INSERT INTO refresh_tokens (token, user_id, app_id, expires_at) VALUES (?, ?, ?, ?)");
    $stmt->execute([$token, $userId, $appId, $expiresAt]);
    
    return $token;
}

function validateRefreshToken($token) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > UTC_TIMESTAMP()");
    $stmt->execute([$token]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function revokeRefreshToken($token) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("DELETE FROM refresh_tokens WHERE token = ?");
    return $stmt->execute([$token]);
}

function revokeAllRefreshTokens($userId, $appId) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("DELETE FROM refresh_tokens WHERE user_id = ? AND app_id = ?");
    return $stmt->execute([$userId, $appId]);
}
?> 