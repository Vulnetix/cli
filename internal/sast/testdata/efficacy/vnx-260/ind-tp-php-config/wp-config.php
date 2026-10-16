<?php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp_prod' );
~>define( 'DB_PASSWORD', 'Wp-Pr0d-9x' );
define( 'DB_HOST', 'db.internal' );
~>define('SMTP_PASS', "Wp-Sm7p-Pass");

$table_prefix = 'wp_';
require_once ABSPATH . 'wp-settings.php';
