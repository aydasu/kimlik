<?php
if (file_exists('config.php')) {
    require_once 'config.php';
    require_once 'database.php';
    if (Database::isConfigured()) {
        header('Location: index.php');
        exit();
    }
}

$error = '';
$success = '';

if ($_POST) {
    $host = $_POST['db_host'] ?? '';
    $name = $_POST['db_name'] ?? '';
    $user = $_POST['db_user'] ?? '';
    $pass = $_POST['db_pass'] ?? '';
    $admin_email = $_POST['admin_email'] ?? '';
    $admin_password = $_POST['admin_password'] ?? '';
    
    if (empty($host) || empty($name) || empty($user) || empty($admin_email) || empty($admin_password)) {
        $error = 'Tüm alanlar gereklidir.';
    } else {
        // Test database connection
        try {
            $pdo = new PDO("mysql:host=$host;dbname=$name", $user, $pass);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Create config file
            $config = "<?php\n";
            $config .= "define('DB_HOST', '$host');\n";
            $config .= "define('DB_NAME', '$name');\n";
            $config .= "define('DB_USER', '$user');\n";
            $config .= "define('DB_PASS', '$pass');\n";
            $config .= "define('JWT_SECRET', '" . bin2hex(random_bytes(32)) . "');\n";
            $config .= "define('APP_NAME', 'Kimlik');\n";
            $config .= "define('APP_URL', 'http://' . \$_SERVER['HTTP_HOST'] . dirname(\$_SERVER['PHP_SELF']));\n";
            $config .= "define('APP_VERSION', '1.0.0');\n";
            $config .= "define('PASSWORD_MIN_LENGTH', 6);\n";
            $config .= "define('TOKEN_EXPIRY', 3600);\n";
            $config .= "define('AUTH_CODE_EXPIRY', 600);\n";
            $config .= "define('EMAIL_DOMAIN', $_SERVER['HTTP_HOST']);\n";
            $config .= "?>";
            
            file_put_contents('config.php', $config);
            
            // Create database tables
            require_once 'config.php';
            require_once 'database.php';
            Database::createTables();
            
            // Create admin user
            $hashedPassword = password_hash($admin_password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (nickname, password, name, is_admin, created_at) VALUES (?, ?, 'Yönetici', 1, NOW())");
            $stmt->execute([$admin_email, $hashedPassword]);
            
            $success = 'Kurulum başarıyla tamamlandı! Şimdi giriş yapabilirsiniz.';
        } catch (Exception $e) {
            $error = 'Veritabanı bağlantısı başarısız: ' . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Kimlik Kurulum</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="setup-form">
            <h1>Kimlik Kurulum</h1>
            
            <?php if ($error): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success"><?php echo htmlspecialchars($success); ?></div>
                <a href="login.php" class="btn">Giriş Sayfasına Git</a>
            <?php else: ?>
                <form method="POST">
                    <h3>Veritabanı Yapılandırması</h3>
                    <input type="text" name="db_host" placeholder="Veritabanı Sunucusu" value="localhost" required>
                    <input type="text" name="db_name" placeholder="Veritabanı Adı" required>
                    <input type="text" name="db_user" placeholder="Veritabanı Kullanıcı Adı" required>
                    <input type="password" name="db_pass" placeholder="Veritabanı Şifresi">
                    
                    <h3>Yönetici Hesabı</h3>
                    <input type="text" name="admin_email" placeholder="Yönetici Kullanıcı Adı" required>
                    <input type="password" name="admin_password" placeholder="Yönetici Şifresi" required>
                    
                    <button type="submit" class="btn">Kimlik'i Kur</button>
                </form>
            <?php endif; ?>
        </div>
    </div>
</body>
</html> 