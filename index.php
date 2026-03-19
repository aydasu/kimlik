<?php
session_start();
require_once 'config.php';
require_once 'database.php';
require_once 'functions.php';

// Handle logout
if (isset($_GET['logout'])) {
    $_SESSION = array();
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 3600, '/');
    }
    session_destroy();
    header('Location: login.php');
    exit();
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$user_id = $_SESSION['user_id'];
$user = getUserById($user_id);
$error = '';
$success = '';

$pdo = Database::connect();

// --- Profile Update Logic ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    $name = $_POST['name'] ?? '';
    $recoveryEmail = $_POST['recovery_email'] ?? '';
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    
    if (empty($name)) {
        $error = 'Ad gereklidir.';
    } else {
        $stmt = $pdo->prepare("UPDATE users SET name = ?, recovery_email = ? WHERE id = ?");
        $stmt->execute([$name, $recoveryEmail, $user_id]);
        
        // Profile picture handling
        if (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] === UPLOAD_ERR_OK) {
            try {
                $profilePicturePath = handleProfilePictureUpload($_FILES['profile_picture']);
                updateUserProfilePicture($user_id, '/'.$profilePicturePath);
            } catch (Exception $e) {
                $error = $e->getMessage();
            }
        }
        
        // Password handling
        if (!empty($currentPassword) && !empty($newPassword)) {
            if (!password_verify($currentPassword, $user['password'])) {
                $error = 'Mevcut şifre yanlış.';
            } elseif (strlen($newPassword) < PASSWORD_MIN_LENGTH) {
                $error = 'Yeni şifre en az ' . PASSWORD_MIN_LENGTH . ' karakter uzunluğunda olmalıdır.';
            } else {
                $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
                $stmt->execute([$hashedPassword, $user_id]);
                $success = 'Profil ve şifre başarıyla güncellendi!';
            }
        } else {
            if (!$error) $success = 'Profil başarıyla güncellendi!';
        }
    }
}

// --- App Creation Logic ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_app'])) {
    $name = $_POST['app_name'] ?? '';
    $description = $_POST['description'] ?? '';
    $redirectUri = $_POST['redirect_uri'] ?? '';
    
    if (empty($name) || empty($redirectUri)) {
        $error = 'Uygulama adı ve yönlendirme URI\'si gereklidir.';
    } elseif (!filter_var($redirectUri, FILTER_VALIDATE_URL)) {
        $error = 'Geçersiz yönlendirme URI formatı.';
    } else {
        $result = createApp($user_id, $name, $description, $redirectUri);
        if ($result['success']) {
            $_SESSION['new_app_secret'] = $result['client_secret'];
            $success = 'Uygulama başarıyla oluşturuldu!';
        } else {
            $error = 'Uygulama oluşturulamadı.';
        }
    }
}

// --- App Deletion Logic ---
if (isset($_GET['delete_app']) && is_numeric($_GET['delete_app'])) {
    $stmt = $pdo->prepare("DELETE FROM apps WHERE id = ? AND user_id = ?");
    $stmt->execute([$_GET['delete_app'], $user_id]);
    $success = 'Uygulama başarıyla silindi!';
}

// --- Secret Refresh Logic ---
if (isset($_GET['refresh_secret']) && is_numeric($_GET['refresh_secret'])) {
    $newSecret = bin2hex(random_bytes(32)); 
    $hashedSecret = password_hash($newSecret, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("UPDATE apps SET client_secret = ?, secret_shown = FALSE WHERE id = ? AND user_id = ?");
    if ($stmt->execute([$hashedSecret, $_GET['refresh_secret'], $user_id])) {
        $_SESSION['new_app_secret'] = $newSecret;
        $success = 'İstemci anahtarı başarıyla yenilendi!';
    } else {
        $error = 'İstemci anahtarı yenilenemedi.';
    }
}

// --- App Deauthorization Logic ---
if (isset($_GET['revoke']) && is_numeric($_GET['revoke'])) {
    $appId = $_GET['revoke'];
    // Revoke all tokens and codes first
    revokeAllRefreshTokens($user_id, $appId);
    revokeAllAuthorizationCodes($user_id, $appId);
    
    // Then delete the authorization record
    $stmt = $pdo->prepare("DELETE FROM user_app_authorizations WHERE user_id = ? AND app_id = ?");
    $stmt->execute([$user_id, $appId]);
    $success = 'Uygulama yetkisi başarıyla kaldırıldı!';
}

// Refresh data for rendering
$user = getUserById($user_id);
$apps = getUserApps($user_id);
$authorizedApps = getUserAuthorizedApps($user_id);
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kimlik - Panel</title>
    <link rel="stylesheet" href="wvisual/css/wvisual.css">
    <style>
        .section-title {
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--wv-border);
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <header class="wv-header">
        <div class="wv-container wv-header-content">
            <a href="index.php" class="wv-logo">Kimlik</a>
            <nav class="wv-nav">
                <?php if ($user['profile_picture']): ?>
                    <img src="<?php echo htmlspecialchars($user['profile_picture']); ?>" alt="Profile" class="wv-avatar-small">
                <?php else: ?>
                    <div class="wv-avatar-small" style="background:#dee2e6; display:flex; align-items:center; justify-content:center; color:#6c757d; font-size:14px; font-weight:bold;">
                        <?php echo strtoupper(substr($user['name'], 0, 1)); ?>
                    </div>
                <?php endif; ?>
                <span class="wv-text-muted" style="font-weight: 500;"><?php echo htmlspecialchars($user['name']); ?></span>
                <a href="?logout=1" class="wv-btn wv-btn-secondary" style="margin-left: 1rem;">Çıkış</a>
            </nav>
        </div>
    </header>
    
    <main class="wv-container wv-mt-4 wv-mb-4">
        
        <?php if ($error): ?>
            <div class="wv-alert wv-alert-error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="wv-alert wv-alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <div class="wv-grid" style="grid-template-columns: 1fr 2fr; gap: 2rem; align-items: start;">
            <!-- Profil Bölümü (Sol Kolon) -->
            <div class="wv-card">
                <h2 class="section-title">Profil</h2>
                <form method="POST" enctype="multipart/form-data">
                    <div class="wv-text-center wv-mb-3">
                        <?php if ($user['profile_picture']): ?>
                            <img src="<?php echo htmlspecialchars($user['profile_picture']); ?>" alt="Profil Fotoğrafı" class="wv-profile-pic">
                        <?php else: ?>
                            <div class="wv-profile-pic" style="margin: 0 auto; display: flex; align-items: center; justify-content: center; background: #e9ecef; color: #adb5bd; font-size: 3rem;">
                                👤
                            </div>
                        <?php endif; ?>
                        
                        <div class="wv-mt-2">
                            <input type="file" name="profile_picture" accept="image/jpeg,image/png,image/gif" class="wv-input" style="font-size: 0.8rem; padding: 0.25rem;">
                        </div>
                    </div>
                    
                    <div class="wv-form-group">
                        <label class="wv-label">E-posta Adresi</label>
                        <input type="email" value="<?php echo htmlspecialchars(generateEmail($user['nickname'])); ?>" class="wv-input" disabled>
                    </div>
                    
                    <div class="wv-form-group">
                        <label class="wv-label">Ad Soyad</label>
                        <input type="text" name="name" value="<?php echo htmlspecialchars($user['name']); ?>" class="wv-input" required>
                    </div>
                    
                    <div class="wv-form-group">
                        <label class="wv-label">Kurtarma E-postası</label>
                        <input type="email" name="recovery_email" value="<?php echo htmlspecialchars($user['recovery_email'] ?? ''); ?>" class="wv-input" placeholder="ornek@gmail.com">
                    </div>
                    
                    <hr style="border:0; border-top:1px solid var(--wv-border); margin: 1.5rem 0;">
                    
                    <h4 class="wv-mb-2">Şifre Değiştir</h4>
                    <div class="wv-form-group">
                        <label class="wv-label">Mevcut Şifre</label>
                        <input type="password" name="current_password" class="wv-input">
                    </div>
                    
                    <div class="wv-form-group">
                        <label class="wv-label">Yeni Şifre</label>
                        <input type="password" name="new_password" class="wv-input">
                    </div>
                    
                    <button type="submit" name="update_profile" class="wv-btn wv-btn-primary wv-btn-block wv-mt-3">Profili Güncelle</button>
                </form>
            </div>

            <!-- Sağ Kolon (Uygulamalar & Yetkilendirmeler) -->
            <div class="wv-flex-col" style="gap: 2rem;">
                
                <!-- Benim Uygulamalarım -->
                <div class="wv-card">
                    <h2 class="section-title">Uygulamalarım</h2>
                    
                    <?php if (empty($apps)): ?>
                        <p class="wv-mb-3">Henüz hiç uygulama oluşturmadınız.</p>
                    <?php else: ?>
                        <div class="wv-grid wv-grid-2 wv-mb-4">
                            <?php foreach ($apps as $app): ?>
                                <div style="border: 1px solid var(--wv-border); border-radius: var(--wv-radius-sm); padding: 1rem;">
                                    <div class="wv-flex wv-justify-between wv-items-center wv-mb-2">
                                        <h4 style="margin:0;"><?php echo htmlspecialchars($app['name']); ?></h4>
                                        <a href="?delete_app=<?php echo $app['id']; ?>" class="wv-btn wv-btn-danger" style="padding: 0.1rem 0.5rem; font-size: 0.75rem;" onclick="return confirm('Bu uygulamayı silmek istediğinizden emin misiniz?')">Sil</a>
                                    </div>
                                    <p style="font-size: 0.85rem; min-height: 2.5em;"><?php echo htmlspecialchars($app['description'] ?? 'Açıklama yok'); ?></p>
                                    
                                    <div class="wv-mt-2">
                                        <strong class="wv-label" style="font-size: 0.85rem;">İstemci ID</strong>
                                        <div class="wv-code-block wv-mb-2" data-copy="<?php echo htmlspecialchars($app['client_id']); ?>">
                                            <span style="font-size: 0.75rem;"><?php echo htmlspecialchars($app['client_id']); ?></span>
                                            <span class="wv-copy-icon">📋</span>
                                        </div>
                                        
                                        <div class="wv-flex wv-justify-between wv-items-center">
                                            <strong class="wv-label" style="font-size: 0.85rem; margin:0;">İstemci Anahtarı</strong>
                                            <a href="?refresh_secret=<?php echo $app['id']; ?>" style="font-size: 0.75rem;" onclick="return confirm('Mevcut anahtarı geçersiz kılacaktır. Onaylıyor musunuz?')">🔄 Yenile</a>
                                        </div>
                                        <?php if (isset($_SESSION['new_app_secret']) && $app['secret_shown'] == 0): ?>
                                            <div class="wv-code-block wv-mb-2" style="border-color: var(--wv-success); font-size: 0.75rem;" data-copy="<?php echo htmlspecialchars($_SESSION['new_app_secret']); ?>">
                                                <span><?php echo htmlspecialchars($_SESSION['new_app_secret']); ?></span>
                                                <span class="wv-copy-icon">📋</span>
                                            </div>
                                            <?php unset($_SESSION['new_app_secret']); ?>
                                            <small class="wv-text-muted" style="color: var(--wv-warning); font-size:0.75rem;">⚠️ Sadece bir kez görünür.</small>
                                        <?php else: ?>
                                            <div class="wv-code-block wv-mb-2">
                                                <span>••••••••••••••••••••••••••••••••</span>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <div style="background: var(--wv-background); padding: 1.5rem; border-radius: var(--wv-radius-sm);">
                        <h4 class="wv-mb-3">Yeni Uygulama Oluştur</h4>
                        <form method="POST">
                            <div class="wv-form-group">
                                <label class="wv-label" style="font-size:0.85rem;">Uygulama Adı</label>
                                <input type="text" name="app_name" class="wv-input" required>
                            </div>
                            <div class="wv-form-group">
                                <label class="wv-label" style="font-size:0.85rem;">Açıklama</label>
                                <textarea name="description" class="wv-textarea" rows="2"></textarea>
                            </div>
                            <div class="wv-form-group">
                                <label class="wv-label" style="font-size:0.85rem;">Yönlendirme URI'si</label>
                                <input type="url" name="redirect_uri" class="wv-input" placeholder="https://uygulamaniz.com/callback" required>
                            </div>
                            <button type="submit" name="create_app" class="wv-btn wv-btn-primary">Oluştur</button>
                        </form>
                    </div>
                </div>

                <!-- Yetkili Uygulamalar -->
                <div class="wv-card">
                    <h2 class="section-title">Yetkili Uygulamalar</h2>
                    <?php if (empty($authorizedApps)): ?>
                        <p class="wv-mb-0">Henüz hiçbir uygulamaya hesabınıza erişim izni vermediniz.</p>
                    <?php else: ?>
                        <div class="wv-grid wv-grid-2">
                            <?php foreach ($authorizedApps as $app): ?>
                                <div style="border: 1px solid var(--wv-border); border-radius: var(--wv-radius-sm); padding: 1rem;">
                                    <div class="wv-flex wv-items-center wv-mb-2">
                                        <div style="width: 32px; height: 32px; background: #e9ecef; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-weight: bold; color: #495057; margin-right: 0.75rem;">
                                            <?php echo strtoupper(substr($app['name'], 0, 1)); ?>
                                        </div>
                                        <h4 style="margin:0;"><?php echo htmlspecialchars($app['name']); ?></h4>
                                    </div>
                                    <p style="font-size: 0.85rem;" class="wv-text-muted">
                                        Yetki Tarihi: <?php echo date('d M Y', strtotime($app['authorized_at'])); ?>
                                    </p>
                                    <div class="wv-mt-3">
                                        <a href="?revoke=<?php echo $app['id']; ?>" class="wv-btn wv-btn-danger wv-btn-block" style="font-size: 0.85rem;" onclick="return confirm('Bu uygulamanın hesabınıza erişimini kaldırmak istediğinizden emin misiniz?')">Erişimi Kaldır</a>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>

            </div>
        </div>
    </main>
    <script src="wvisual/js/wvisual.js"></script>
</body>
</html>