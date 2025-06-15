<?php
define('DB_HOST', 'localhost');
define('DB_NAME', 'aydasso');
define('DB_USER', 'root');
define('DB_PASS', '123123123');
define('JWT_SECRET', '9450a0e535da969919c62c083410961e2ccb2bdf4821c2a29fe8c5c8b7da633f');
define('APP_NAME', 'Kimlik');
define('APP_URL', 'http://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']));
define('APP_VERSION', '1.0.0');
define('PASSWORD_MIN_LENGTH', 6);
define('TOKEN_EXPIRY', 3600);
define('AUTH_CODE_EXPIRY', 600);
define('EMAIL_DOMAIN', 'ayda.su');
?>