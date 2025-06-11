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
<html>
<head>
    <title>Kimlik - Giriş</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="auth-form">
            <h1>Kimlik'e Giriş Yap</h1>
            
            <?php if ($error): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <input type="text" name="email" placeholder="E-posta Adresi veya Kullanıcı Adı" pattern="[^\s]*" title="Kullanıcı adında boşluk kullanılamaz" required>
                <input type="password" name="password" placeholder="Şifre" required>
                <button type="submit" class="btn">Giriş Yap</button>
            </form>
            
            <p><a href="register.php">Hesabınız yok mu? Kayıt Ol</a></p>
        </div>
    </div>
</body>
</html> 