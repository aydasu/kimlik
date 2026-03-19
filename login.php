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

if ($_POST) {
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($email) || empty($password)) {
        $error = 'E-posta ve şifre gereklidir.';
    } else {
        // Check if input is a username or email
        $user = null;
        // Input is a username, try to find user by nickname
        $nickname = str_replace('@' . EMAIL_DOMAIN, '', $email);
        $user = getUserByNickname($nickname);
        
        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            
            // Check for OAuth redirect
            if (isset($_SESSION['oauth_redirect'])) {
                $redirect = $_SESSION['oauth_redirect'];
                unset($_SESSION['oauth_redirect']);
                header('Location: ' . $redirect);
            } else {
                header('Location: index.php');
            }
            exit();
        } else {
            $error = 'Geçersiz e-posta/kullanıcı adı veya şifre.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kimlik - Giriş</title>
    <link rel="stylesheet" href="wvisual/css/wvisual.css">
</head>
<body class="wv-auth-layout">
    <div class="wv-auth-card wv-card wv-animate-fade-in">
        <div class="wv-text-center wv-mb-4">
            <h1 class="wv-logo" style="font-size: 2.5rem; margin-bottom: 0.5rem; display: inline-block;">Kimlik</h1>
            <p>Hesabınıza giriş yapın</p>
        </div>
        
        <?php if ($error): ?>
            <div class="wv-alert wv-alert-error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <form method="POST">
            <div class="wv-form-group">
                <label class="wv-label">E-posta Adresi veya Kullanıcı Adı</label>
                <input type="text" name="email" class="wv-input" placeholder="ornek@ayda.su" pattern="[^\s]*" title="Kullanıcı adında boşluk kullanılamaz" required>
            </div>
            <div class="wv-form-group">
                <label class="wv-label">Şifre</label>
                <input type="password" name="password" class="wv-input" placeholder="••••••••" required>
            </div>
            <button type="submit" class="wv-btn wv-btn-primary wv-btn-block wv-mt-4">Giriş Yap</button>
        </form>
        
        <div class="wv-text-center wv-mt-4">
            <p class="wv-mb-0">Hesabınız yok mu? <a href="register.php">Kayıt Ol</a></p>
        </div>
    </div>
    <script src="wvisual/js/wvisual.js"></script>
</body>
</html> 