<?php
header('X-Requested-Page: ' . basename($_SERVER['PHP_SELF']));
header('Content-Disposition: attachment; filename="' . basename($_GET['f']) . '"');

// header('Location: ' . $_GET['url']);
$help = "Never call header('Location: ' . \$_GET['url']) with raw input";

header('Location: /login.php');
