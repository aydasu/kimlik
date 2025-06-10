<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$error = '';
$success = '';

// Handle app creation
if ($_POST && isset($_POST['create_app'])) {
    $name = $_POST['name'] ?? '';
    $description = $_POST['description'] ?? '';
    $redirectUri = $_POST['redirect_uri'] ?? '';
    
    if (empty($name) || empty($redirectUri)) {
        $error = 'Uygulama adı ve yönlendirme URI\'si gereklidir.';
    } elseif (!filter_var($redirectUri, FILTER_VALIDATE_URL)) {
        $error = 'Geçersiz yönlendirme URI formatı.';
    } else {
        $result = createApp($_SESSION['user_id'], $name, $description, $redirectUri);
        if ($result['success']) {
            $_SESSION['new_app_secret'] = $result['client_secret'];
            $success = 'Uygulama başarıyla oluşturuldu!';
        } else {
            $error = 'Uygulama oluşturulamadı.';
        }
    }
}

// Handle app deletion
if (isset($_GET['delete']) && is_numeric($_GET['delete'])) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("DELETE FROM apps WHERE id = ? AND user_id = ?");
    $stmt->execute([$_GET['delete'], $_SESSION['user_id']]);
    $success = 'Uygulama başarıyla silindi!';
}

// Handle secret refresh
if (isset($_GET['refresh_secret']) && is_numeric($_GET['refresh_secret'])) {
    $pdo = Database::connect();
    $newSecret = bin2hex(random_bytes(32)); // Generate new secret
    $hashedSecret = password_hash($newSecret, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("UPDATE apps SET client_secret = ?, secret_shown = FALSE WHERE id = ? AND user_id = ?");
    if ($stmt->execute([$hashedSecret, $_GET['refresh_secret'], $_SESSION['user_id']])) {
        $_SESSION['new_app_secret'] = $newSecret;
        $success = 'İstemci anahtarı başarıyla yenilendi!';
    } else {
        $error = 'İstemci anahtarı yenilenemedi.';
    }
}

$apps = getUserApps($_SESSION['user_id']);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Kimlik - Uygulamalarım</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .btn-small {
            padding: 2px 8px;
            font-size: 0.8em;
            margin-left: 8px;
        }
        .detail-row {
            display: flex;
            align-items: center;
            gap: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Kimlik - Uygulamalarım</h1>
            <nav>
                <a href="index.php">Kontrol Paneli</a>
                <a href="profile.php">Profil</a>
                <a href="authorized.php">Yetkili Uygulamalar</a>
                <a href="index.php?logout=1">Çıkış</a>
            </nav>
        </header>
        
        <main>
            <h2>Uygulamalarım</h2>
            
            <?php if ($error): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            
            <div class="create-app-form">
                <h3>Yeni Uygulama Oluştur</h3>
                <form method="POST">
                    <input type="text" name="name" placeholder="Uygulama Adı" required>
                    <textarea name="description" placeholder="Uygulama Açıklaması (isteğe bağlı)"></textarea>
                    <input type="url" name="redirect_uri" placeholder="Yönlendirme URI'si" required>
                    <button type="submit" name="create_app" class="btn">Uygulama Oluştur</button>
                </form>
            </div>
            
            <div class="apps-list">
                <?php if (empty($apps)): ?>
                    <p>Henüz hiç uygulama oluşturmadınız.</p>
                <?php else: ?>
                    <?php foreach ($apps as $app): ?>
                        <div class="app-card" data-app-id="<?php echo $app['id']; ?>">
                            <h3><?php echo htmlspecialchars($app['name']); ?></h3>
                            <p><?php echo htmlspecialchars($app['description'] ?? 'Açıklama yok'); ?></p>
                            
                            <div class="app-details">
                                <div class="detail-row">
                                    <strong>İstemci ID:</strong> 
                                    <code><?php echo htmlspecialchars($app['client_id']); ?></code>
                                </div>
                                <div class="detail-row">
                                    <strong>İstemci Anahtarı:</strong> 
                                    <?php if (isset($_SESSION['new_app_secret']) && $app['secret_shown'] == 0): ?>
                                        <code><?php echo htmlspecialchars($_SESSION['new_app_secret']); ?></code>
                                        <?php unset($_SESSION['new_app_secret']); ?>
                                    <?php else: ?>
                                        <code>Hidden</code>
                                    <?php endif; ?>
                                    <a href="?refresh_secret=<?php echo $app['id']; ?>" class="btn btn-small" onclick="return confirm('İstemci anahtarını yenilemek istediğinizden emin misiniz? Bu işlem mevcut anahtarı geçersiz kılacaktır.')">Yenile</a>
                                </div>
                                <div class="detail-row">
                                    <strong>Yönlendirme URI'si:</strong> 
                                    <?php echo htmlspecialchars($app['redirect_uri']); ?>
                                </div>
                                <div class="detail-row">
                                    <strong>Oluşturulma:</strong> 
                                    <?php echo date('Y-m-d H:i', strtotime($app['created_at'])); ?>
                                </div>
                            </div>
                            
                            <div class="app-actions">
                                <a href="?delete=<?php echo $app['id']; ?>" class="btn btn-danger" onclick="return confirm('Bu uygulamayı silmek istediğinizden emin misiniz?')">Sil</a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </main>
    </div>
    
    <script>
    </script>
</body>
</html> 