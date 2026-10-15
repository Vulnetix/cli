<?php
header("Location: /account/settings?tab=" . urlencode($_GET['tab']));
$base = rtrim(getenv('APP_URL'), '/');
header('Location: ' . $base . '/home');
