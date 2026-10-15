<?php
session_start();
session_destroy();

$target = $_GET['continue'] ?? '/';
$dest = $target;

~>header("Location: $dest");
exit;
