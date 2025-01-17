<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// Handle app deauthorization
if (isset($_GET['revoke']) && is_numeric($_GET['revoke'])) {
    $pdo = Database::connect();
    $stmt = $pdo->prepare("DELETE FROM user_app_authorizations WHERE user_id = ? AND app_id = ?");
    $stmt->execute([$_SESSION['user_id'], $_GET['revoke']]);
    $success = 'Uygulama yetkisi başarıyla kaldırıldı!';
}

$authorizedApps = getUserAuthorizedApps($_SESSION['user_id']);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Kimlik - Yetkili Uygulamalar</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Kimlik - Yetkili Uygulamalar</h1>
            <nav>
                <a href="index.php">Kontrol Paneli</a>
                <a href="profile.php">Profil</a>
                <a href="apps.php">Uygulamalarım</a>
                <a href="index.php?logout=1">Çıkış</a>
            </nav>
        </header>
        
        <main>
            <h2>Yetkili Uygulamalar</h2>
            
            <?php if (isset($success)): ?>
                <div class="success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            
            <div class="authorized-apps">
                <?php if (empty($authorizedApps)): ?>
                    <p>Henüz hiç uygulamaya yetki vermediniz.</p>
                <?php else: ?>
                    <?php foreach ($authorizedApps as $app): ?>
                        <div class="app-card">
                            <h3><?php echo htmlspecialchars($app['name']); ?></h3>
                            <p><?php echo htmlspecialchars($app['description'] ?? 'Açıklama yok'); ?></p>
                            
                            <div class="app-details">
                                <div class="detail-row">
                                    <strong>Yetkilendirme:</strong> 
                                    <?php echo date('Y-m-d H:i', strtotime($app['authorized_at'])); ?>
                                </div>
                                <div class="detail-row">
                                    <strong>Yönlendirme URI'si:</strong> 
                                    <?php echo htmlspecialchars($app['redirect_uri']); ?>
                                </div>
                            </div>
                            
                            <div class="app-actions">
                                <a href="?revoke=<?php echo $app['id']; ?>" class="btn btn-danger" onclick="return confirm('Bu uygulamanın erişimini kaldırmak istediğinizden emin misiniz?')">Erişimi Kaldır</a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </main>
    </div>
</body>
</html> 