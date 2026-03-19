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
            'email' => generateEmail($user['nickname']),
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
            'email' => generateEmail($user['nickname']),
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
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kimlik - Erişim Yetkilendirme</title>
    <link rel="stylesheet" href="wvisual/css/wvisual.css">
    <style>
        .wv-oauth-card {
            max-width: 480px;
            margin: 4rem auto;
            text-align: center;
        }
        .wv-app-logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, rgba(79, 70, 229, 0.1), rgba(14, 165, 233, 0.1));
            border-radius: 20px;
            margin: 0 auto 1.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--wv-primary);
            border: 1px solid rgba(79, 70, 229, 0.2);
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
        }
        .wv-permissions-box {
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--wv-border);
            border-radius: var(--wv-radius);
            padding: 1.5rem;
            margin: 2rem 0;
            text-align: left;
        }
    </style>
</head>
<body>
    <div class="wv-container">
        <div class="wv-card wv-oauth-card wv-animate-fade-in">
            <?php if ($error): ?>
                <div class="wv-alert wv-alert-error"><?php echo htmlspecialchars($error); ?></div>
                <div class="wv-mt-4">
                    <a href="index.php" class="wv-btn wv-btn-secondary">Geri Dön</a>
                </div>
            <?php elseif (isset($app)): ?>
                <div class="wv-app-logo">
                    <?php echo strtoupper(substr($app['name'], 0, 1)); ?>
                </div>
                
                <h1 style="font-size: 1.75rem; margin-bottom: 0.5rem;"><?php echo htmlspecialchars($app['name']); ?></h1>
                
                <p class="wv-text-muted">
                    <strong style="color: var(--wv-text-main);">Kimlik</strong> hesabınıza erişim izni istiyor.
                </p>
                
                <?php if (!empty($app['description'])): ?>
                    <p style="font-size: 0.9rem;" class="wv-mb-3"><?php echo htmlspecialchars($app['description']); ?></p>
                <?php endif; ?>

                <div class="wv-permissions-box">
                    <h3 style="font-size: 1rem; margin-bottom: 1rem;">Uygulama şunlara erişebilecek:</h3>
                    
                    <div class="wv-flex wv-items-center wv-mb-2">
                        <span style="color: var(--wv-success); margin-right: 0.75rem; font-size: 1.25rem;">✓</span>
                        <div class="wv-flex-col">
                            <span style="font-weight: 600;">Temel Profil Bilgileri</span>
                            <span class="wv-text-muted" style="font-size: 0.85rem;">Adınız, kullanıcı adınız ve profil fotoğrafınız.</span>
                        </div>
                    </div>
                </div>

                <div class="wv-mb-4" style="font-size: 0.85rem; color: var(--wv-text-muted);">
                    <span style="color: var(--wv-primary);">ℹ</span> İzin verdiğinizde <strong><?php echo htmlspecialchars($app['redirect_uri']); ?></strong> adresine yönlendirileceksiniz.
                </div>

                <form method="POST">
                    <div class="wv-flex wv-gap-4">
                        <button type="submit" name="authorize" value="no" class="wv-btn wv-btn-secondary" style="flex: 1;">İptal</button>
                        <button type="submit" name="authorize" value="yes" class="wv-btn wv-btn-primary" style="flex: 2;">Erişime İzin Ver</button>
                    </div>
                </form>
            <?php endif; ?>
        </div>
    </div>
    <script src="wvisual/js/wvisual.js"></script>
</body>
</html> 