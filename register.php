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
<html>
<head>
    <title>Kimlik - Kayıt</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="auth-form">
            <h1>Kimlik'e Kayıt Ol</h1>
            
            <?php if ($error): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success"><?php echo htmlspecialchars($success); ?></div>
                <a href="login.php" class="btn">Giriş Sayfasına Git</a>
            <?php else: ?>
                <form method="POST">
                    <input type="text" name="name" placeholder="Ad Soyad" required>
                    <div class="nickname-container">
                        <input type="text" name="nickname" placeholder="Kullanıcı Adı" pattern="[^\s]*" title="Kullanıcı adında boşluk kullanılamaz" required>
                        <div class="email-suffix">@ayda.su</div>
                    </div>
                    <small class="email-info">Bu kullanıcı adınız e-posta adresiniz olacak</small>
                    <input type="password" name="password" placeholder="Şifre" required>
                    <input type="password" name="confirm_password" placeholder="Şifre Tekrar" required>
                    <button type="submit" class="btn">Kayıt Ol</button>
                </form>
            <?php endif; ?>
            
            <p><a href="login.php">Zaten hesabın var mı? Giriş Yap</a></p>
        </div>
    </div>
</body>
</html> 