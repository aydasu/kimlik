<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$user = getUserById($_SESSION['user_id']);
$error = '';
$success = '';

if ($_POST) {
    $name = $_POST['name'] ?? '';
    $nickname = $_POST['nickname'] ?? '';
    $recoveryEmail = $_POST['recovery_email'] ?? '';
    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    
    if (empty($name)) {
        $error = 'Ad gereklidir.';
    } else {
        $pdo = Database::connect();
        
        // Update basic profile info
        $stmt = $pdo->prepare("UPDATE users SET name = ?, recovery_email = ? WHERE id = ?");
        $stmt->execute([$name, $recoveryEmail, $_SESSION['user_id']]);
        
        // Handle profile picture upload
        if (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] === UPLOAD_ERR_OK) {
            try {
                $profilePicturePath = handleProfilePictureUpload($_FILES['profile_picture']);
                updateUserProfilePicture($_SESSION['user_id'], '/'.$profilePicturePath);
            } catch (Exception $e) {
                $error = $e->getMessage();
            }
        }
        
        // Handle password change
        if (!empty($currentPassword) && !empty($newPassword)) {
            if (!password_verify($currentPassword, $user['password'])) {
                $error = 'Mevcut şifre yanlış.';
            } elseif (strlen($newPassword) < PASSWORD_MIN_LENGTH) {
                $error = 'Yeni şifre en az ' . PASSWORD_MIN_LENGTH . ' karakter uzunluğunda olmalıdır.';
            } else {
                $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
                $stmt->execute([$hashedPassword, $_SESSION['user_id']]);
                $success = 'Profil başarıyla güncellendi!';
            }
        } else {
            $success = 'Profil başarıyla güncellendi!';
        }
        
        // Refresh user data
        $user = getUserById($_SESSION['user_id']);
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Kimlik - Profil</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>Kimlik - Profil</h1>
            <nav>
                <a href="index.php">Kontrol Paneli</a>
                <a href="apps.php">Uygulamalarım</a>
                <a href="authorized.php">Yetkili Uygulamalar</a>
                <a href="index.php?logout=1">Çıkış</a>
            </nav>
        </header>
        
        <main>
            <h2>Profil Ayarları</h2>
            
            <?php if ($error): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            
            <form method="POST" class="profile-form" enctype="multipart/form-data">
                <div class="form-group">
                    <label>Profil Fotoğrafı</label>
                    <?php if ($user['profile_picture']): ?>
                        <div class="current-profile-picture">
                            <img src="<?php echo htmlspecialchars($user['profile_picture']); ?>" alt="Profil Fotoğrafı" style="max-width: 150px; border-radius: 50%;">
                        </div>
                    <?php endif; ?>
                    <input type="file" name="profile_picture" accept="image/jpeg,image/png,image/gif">
                    <small>Maksimum dosya boyutu: 5MB. İzin verilen formatlar: JPG, PNG, GIF</small>
                </div>
                
                <div class="form-group">
                    <label>E-posta Adresi</label>
                    <input type="email" value="<?php echo htmlspecialchars(generateEmail($user['nickname'])); ?>" disabled>
                    <small>@ayda.su e-posta adresiniz değiştirilemez</small>
                </div>
                
                <div class="form-group">
                    <label>Ad Soyad</label>
                    <input type="text" name="name" value="<?php echo htmlspecialchars($user['name']); ?>" required>
                </div>
                
                
                <div class="form-group">
                    <label>Kurtarma E-postası</label>
                    <input type="email" name="recovery_email" value="<?php echo htmlspecialchars($user['recovery_email'] ?? ''); ?>">
                </div>
                
                <h3>Şifre Değiştir</h3>
                <div class="form-group">
                    <label>Mevcut Şifre</label>
                    <input type="password" name="current_password">
                </div>
                
                <div class="form-group">
                    <label>Yeni Şifre</label>
                    <input type="password" name="new_password">
                </div>
                
                <button type="submit" class="btn">Profili Güncelle</button>
            </form>
        </main>
    </div>
</body>
</html> 