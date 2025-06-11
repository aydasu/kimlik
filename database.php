<?php
class Database {
    private static $pdo = null;
    
    public static function connect() {
        if (self::$pdo === null) {
            try {
                self::$pdo = new PDO(
                    "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME,
                    DB_USER,
                    DB_PASS,
                    [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::MYSQL_ATTR_INIT_COMMAND => "SET time_zone = '+00:00'"
                    ]
                );
            } catch (PDOException $e) {
                die("Database connection failed: " . $e->getMessage());
            }
        }
        return self::$pdo;
    }
    
    public static function isConfigured() {
        try {
            $pdo = self::connect();
            $stmt = $pdo->query("SHOW TABLES LIKE 'users'");
            return $stmt->rowCount() > 0;
        } catch (Exception $e) {
            return false;
        }
    }
    
    public static function createTables() {
        $pdo = self::connect();
        
        // Users table
        $pdo->exec("CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nickname VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            profile_picture VARCHAR(255),
            recovery_email VARCHAR(255),
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Apps table
        $pdo->exec("CREATE TABLE IF NOT EXISTS apps (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            client_id VARCHAR(255) UNIQUE NOT NULL,
            client_secret VARCHAR(255) NOT NULL,
            redirect_uri VARCHAR(255) NOT NULL,
            secret_shown BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )");
        
        // Authorization codes table
        $pdo->exec("CREATE TABLE IF NOT EXISTS authorization_codes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            code VARCHAR(255) UNIQUE NOT NULL,
            user_id INT NOT NULL,
            app_id INT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
        )");
        
        // User app authorizations table
        $pdo->exec("CREATE TABLE IF NOT EXISTS user_app_authorizations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            app_id INT NOT NULL,
            authorized_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_user_app (user_id, app_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
        )");

        // Refresh tokens table
        $pdo->exec("CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            token VARCHAR(255) UNIQUE NOT NULL,
            user_id INT NOT NULL,
            app_id INT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
        )");
    }
}
?> 