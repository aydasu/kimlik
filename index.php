<?php
session_start();
require_once 'config.php';
require_once 'database.php';
require_once 'functions.php';

// Handle logout
if (isset($_GET['logout'])) {
    // Clear all session variables
    $_SESSION = array();
    
    // Destroy the session cookie
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 3600, '/');
    }
    
    // Destroy the session
    session_destroy();
    
    // Redirect to login page
    header('Location: login.php');
    exit();
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$user = getUserById($_SESSION['user_id']);
$apps = getUserApps($_SESSION['user_id']);
$authorizedApps = getUserAuthorizedApps($_SESSION['user_id']);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Kimlik - Kontrol Paneli</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Kimlik Kontrol Paneli</h1>
            <nav>
                <a href="profile.php">Profil</a>
                <a href="apps.php">Uygulamalarım</a>
                <a href="authorized.php">Yetkili Uygulamalar</a>
                <a href="?logout=1">Çıkış</a>
            </nav>
        </header>
        
        <main>
            <h2>Hoş geldiniz, <?php echo htmlspecialchars($user['name']); ?>!</h2>
            
            <div class="dashboard-grid">
                <div class="card">
                    <h3>Uygulamalarım</h3>
                    <p><?php echo count($apps); ?> uygulama oluşturuldu</p>
                    <a href="apps.php" class="btn">Uygulamaları Yönet</a>
                </div>
                
                <div class="card">
                    <h3>Yetkili Uygulamalar</h3>
                    <p><?php echo count($authorizedApps); ?> uygulama yetkilendirildi</p>
                    <a href="authorized.php" class="btn">Yetkili Uygulamaları Görüntüle</a>
                </div>
                
                <div class="card">
                    <h3>Profil</h3>
                    <p>Hesap ayarlarınızı yönetin</p>
                    <a href="profile.php" class="btn">Profili Düzenle</a>
                </div>
            </div>
        </main>
    </div>
</body>
</html> 