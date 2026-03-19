<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit();
}

$error = '';
$success = '';

if ($_POST) {
    $name = $_POST['name'] ?? '';
    $nickname = $_POST['nickname'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    
    if (empty($name) || empty($password) || empty($confirmPassword)) {
        $error = 'Ad, şifre ve şifre onayı gereklidir.';
    } elseif ($password !== $confirmPassword) {
        $error = 'Şifreler eşleşmiyor.';
    } elseif (strlen($password) < PASSWORD_MIN_LENGTH) {
        $error = 'Şifre en az ' . PASSWORD_MIN_LENGTH . ' karakter uzunluğunda olmalıdır.';
    } elseif (!empty($nickname) && strpos($nickname, ' ') !== false) {
        $error = 'Kullanıcı adında boşluk kullanılamaz.';
    } else {
        try {
            if (getUserByNickname($nickname)) {
                $error = 'Bu kullanıcı adı zaten kullanılıyor.';
            } else if (createUser($nickname, $password, $name)) {
                $email = generateEmail($nickname);
                $success = "Hesap başarıyla oluşturuldu! E-posta adresiniz: $email";
            } else {
                $error = 'Hesap oluşturulamadı.';
            }
        } catch (Exception $e) {
            $error = 'Hesabınız oluşturulurken bir hata oluştu.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kimlik - Kayıt</title>
    <link rel="stylesheet" href="wvisual/css/wvisual.css">
</head>
<body class="wv-auth-layout">
    <div class="wv-auth-card wv-card wv-animate-fade-in" style="max-width: 500px;">
        <div class="wv-text-center wv-mb-4">
            <h1 class="wv-logo" style="font-size: 2.5rem; margin-bottom: 0.5rem; display: inline-block;">Kimlik</h1>
            <p>Yeni bir hesap oluşturun</p>
        </div>
        
        <?php if ($error): ?>
            <div class="wv-alert wv-alert-error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="wv-alert wv-alert-success"><?php echo htmlspecialchars($success); ?></div>
            <a href="login.php" class="wv-btn wv-btn-primary wv-btn-block wv-mt-4">Giriş Sayfasına Git</a>
        <?php else: ?>
            <form method="POST">
                <div class="wv-form-group">
                    <label class="wv-label">Ad Soyad</label>
                    <input type="text" name="name" class="wv-input" placeholder="Adınız Soyadınız" required>
                </div>
                <div class="wv-form-group">
                    <label class="wv-label">Kullanıcı Adı</label>
                    <div class="wv-input-group">
                        <input type="text" name="nickname" class="wv-input" placeholder="kullanici" pattern="[^\s]*" title="Kullanıcı adında boşluk kullanılamaz" required>
                        <div class="wv-input-suffix">@ayda.su</div>
                    </div>
                    <small class="wv-text-muted wv-mt-1 wv-flex">Bu kullanıcı adınız e-posta adresiniz olacak</small>
                </div>
                <div class="wv-form-group">
                    <label class="wv-label">Şifre</label>
                    <input type="password" name="password" class="wv-input" placeholder="••••••••" required>
                </div>
                <div class="wv-form-group">
                    <label class="wv-label">Şifre Tekrar</label>
                    <input type="password" name="confirm_password" class="wv-input" placeholder="••••••••" required>
                </div>
                <button type="submit" class="wv-btn wv-btn-primary wv-btn-block wv-mt-4">Kayıt Ol</button>
            </form>
        <?php endif; ?>
        
        <div class="wv-text-center wv-mt-4">
            <p class="wv-mb-0">Zaten hesabın var mı? <a href="login.php">Giriş Yap</a></p>
        </div>
    </div>
    <script src="wvisual/js/wvisual.js"></script>
</body>
</html> 