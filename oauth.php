<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

$error = '';

// Authorization endpoint
if (isset($_GET['response_type']) && $_GET['response_type'] === 'code') {
    $clientId = $_GET['client_id'] ?? '';
    $redirectUri = $_GET['redirect_uri'] ?? '';
    $state = $_GET['state'] ?? '';
    
    if (empty($clientId) || empty($redirectUri)) {
        $error = 'Missing required parameters.';
    } else {
        // Validate client
        $pdo = Database::connect();
        $stmt = $pdo->prepare("SELECT * FROM apps WHERE client_id = ?");
        $stmt->execute([$clientId]);
        $app = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$app) {
            $error = 'Invalid client ID.';
        } elseif ($app['redirect_uri'] !== $redirectUri) {
            $error = 'Invalid redirect URI.';
        } else {
            // Check if user is logged in
            if (!isset($_SESSION['user_id'])) {
                $_SESSION['oauth_redirect'] = $_SERVER['REQUEST_URI'];
                header('Location: login.php');
                exit();
            }
            
            // Check if app is already authorized
            if (isAppAuthorized($_SESSION['user_id'], $app['id'])) {
                // Generate authorization code and redirect
                $code = createAuthorizationCode($_SESSION['user_id'], $app['id']);
                $redirectUrl = $redirectUri . '?code=' . $code;
                if (!empty($state)) {
                    $redirectUrl .= '&state=' . urlencode($state);
                }
                header('Location: ' . $redirectUrl);
                exit();
            }
            
            // Show authorization page
            if ($_POST && isset($_POST['authorize'])) {
                if ($_POST['authorize'] === 'yes') {
                    // Authorize the app
                    authorizeUserApp($_SESSION['user_id'], $app['id']);
                    $code = createAuthorizationCode($_SESSION['user_id'], $app['id']);
                    $redirectUrl = $redirectUri . '?code=' . $code;
                    if (!empty($state)) {
                        $redirectUrl .= '&state=' . urlencode($state);
                    }
                    header('Location: ' . $redirectUrl);
                    exit();
                } else {
                    // User denied authorization
                    $redirectUrl = $redirectUri . '?error=access_denied';
                    if (!empty($state)) {
                        $redirectUrl .= '&state=' . urlencode($state);
                    }
                    header('Location: ' . $redirectUrl);
                    exit();
                }
            }
        }
    }
}

// Token endpoint
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['grant_type'])) {
    header('Content-Type: application/json');
    
    if ($_POST['grant_type'] === 'authorization_code') {
        $code = $_POST['code'] ?? '';
        $clientId = $_POST['client_id'] ?? '';
        $clientSecret = $_POST['client_secret'] ?? '';
        $redirectUri = $_POST['redirect_uri'] ?? '';
        
        error_log("Token request received - Code: $code, Client ID: $clientId, Client Secret: $clientSecret, Redirect URI: $redirectUri");
        
        if (empty($code) || empty($clientId) || empty($clientSecret)) {
            error_log("Missing required parameters");
            http_response_code(400);
            echo json_encode(['error' => 'invalid_request']);
            exit();
        }
        
        // Validate client credentials
        $pdo = Database::connect();
        $stmt = $pdo->prepare("SELECT * FROM apps WHERE client_id = ?");
        $stmt->execute([$clientId]);
        $app = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$app || !password_verify($clientSecret, $app['client_secret'])) {
            error_log("Invalid client credentials");
            http_response_code(401);
            echo json_encode(['error' => 'invalid_client']);
            exit();
        }
        
        // Validate authorization code
        $authCode = validateAuthorizationCode($code);
        error_log("Authorization code validation result: " . ($authCode ? "valid" : "invalid"));
        if ($authCode) {
            error_log("Auth code details - User ID: {$authCode['user_id']}, App ID: {$authCode['app_id']}, Expires: {$authCode['expires_at']}, Used: {$authCode['used']}");
        }
        
        if (!$authCode || $authCode['app_id'] != $app['id']) {
            error_log("Invalid or expired authorization code");
            http_response_code(400);
            echo json_encode(['error' => 'invalid_grant']);
            exit();
        }
        
        // Mark code as used
        markAuthorizationCodeUsed($code);
        error_log("Authorization code marked as used");
        
        // Get user info
        $user = getUserById($authCode['user_id']);
        
        // Generate access token (JWT)
        $payload = [
            'sub' => $user['id'],
            'email' => $user['email'],
            'name' => $user['name'],
            'nickname' => $user['nickname'],
            'profile_picture' => $user['profile_picture'],
            'iat' => time(),
            'exp' => time() + TOKEN_EXPIRY,
            'aud' => $clientId
        ];
        
        $accessToken = generateJWT($payload);
        error_log("Access token generated successfully");
        
        // Generate refresh token
        $refreshToken = generateRefreshToken($user['id'], $app['id']);
        
        echo json_encode([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => TOKEN_EXPIRY
        ]);
        exit();
    } elseif ($_POST['grant_type'] === 'refresh_token') {
        $refreshToken = $_POST['refresh_token'] ?? '';
        $clientId = $_POST['client_id'] ?? '';
        $clientSecret = $_POST['client_secret'] ?? '';
        
        if (empty($refreshToken) || empty($clientId) || empty($clientSecret)) {
            http_response_code(400);
            echo json_encode(['error' => 'invalid_request']);
            exit();
        }
        
        // Validate client credentials
        $pdo = Database::connect();
        $stmt = $pdo->prepare("SELECT * FROM apps WHERE client_id = ?");
        $stmt->execute([$clientId]);
        $app = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$app || !password_verify($clientSecret, $app['client_secret'])) {
            http_response_code(401);
            echo json_encode(['error' => 'invalid_client']);
            exit();
        }
        
        // Validate refresh token
        $tokenData = validateRefreshToken($refreshToken);
        if (!$tokenData || $tokenData['app_id'] != $app['id']) {
            http_response_code(400);
            echo json_encode(['error' => 'invalid_grant']);
            exit();
        }
        
        // Get user info
        $user = getUserById($tokenData['user_id']);
        
        // Generate new access token
        $payload = [
            'sub' => $user['id'],
            'email' => $user['email'],
            'name' => $user['name'],
            'nickname' => $user['nickname'],
            'profile_picture' => $user['profile_picture'],
            'iat' => time(),
            'exp' => time() + TOKEN_EXPIRY,
            'aud' => $clientId
        ];
        
        $accessToken = generateJWT($payload);
        
        // Generate new refresh token and revoke old one
        $newRefreshToken = generateRefreshToken($user['id'], $app['id']);
        revokeRefreshToken($refreshToken);
        
        echo json_encode([
            'access_token' => $accessToken,
            'refresh_token' => $newRefreshToken,
            'token_type' => 'Bearer',
            'expires_in' => TOKEN_EXPIRY
        ]);
        exit();
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'unsupported_grant_type']);
        exit();
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Kimlik - Erişim Yetkilendirme</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .oauth-container {
            max-width: 500px;
            margin: 50px auto;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }

        .app-header {
            text-align: center;
            margin-bottom: 30px;
        }

        .app-logo {
            width: 80px;
            height: 80px;
            background: #f8f9fa;
            border-radius: 16px;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            color: #3498db;
        }

        .app-name {
            font-size: 24px;
            color: #2c3e50;
            margin-bottom: 10px;
        }

        .app-description {
            color: #7f8c8d;
            margin-bottom: 20px;
        }

        .permissions-list {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }

        .permissions-list h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 18px;
        }

        .permission-item {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
            color: #34495e;
        }

        .permission-item:last-child {
            margin-bottom: 0;
        }

        .permission-item i {
            color: #27ae60;
            margin-right: 10px;
        }

        .auth-buttons {
            display: flex;
            gap: 15px;
            margin-top: 30px;
        }

        .auth-buttons button {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn-authorize {
            background: #27ae60;
            color: white;
        }

        .btn-authorize:hover {
            background: #219a52;
        }

        .btn-deny {
            background: #e74c3c;
            color: white;
        }

        .btn-deny:hover {
            background: #c0392b;
        }

        .security-info {
            margin-top: 20px;
            padding: 15px;
            background: #e8f4f8;
            border-radius: 6px;
            color: #2980b9;
            font-size: 14px;
        }

        .security-info i {
            margin-right: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="oauth-container">
            <?php if ($error): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php elseif (isset($app)): ?>
                <div class="app-header">
                    <div class="app-logo">
                        <?php echo strtoupper(substr($app['name'], 0, 1)); ?>
                    </div>
                    <h1 class="app-name"><?php echo htmlspecialchars($app['name']); ?></h1>
                    <p class="app-description"><?php echo htmlspecialchars($app['description']); ?></p>
                </div>

                <div class="permissions-list">
                    <h3>Bu uygulama aşağıdaki bilgilere erişebilir:</h3>
                    <div class="permission-item">
                        <i>✓</i>
                        <span>Basit profil bilgilerine erişim</span>
                    </div>
                </div>

                <form method="POST">
                    <div class="auth-buttons">
                        <button type="submit" name="authorize" value="yes" class="btn-authorize">Erişim Yetkilendir</button>
                        <button type="submit" name="authorize" value="no" class="btn-deny">Reddet</button>
                    </div>
                </form>
            <?php endif; ?>
        </div>
    </div>
</body>
</html> 