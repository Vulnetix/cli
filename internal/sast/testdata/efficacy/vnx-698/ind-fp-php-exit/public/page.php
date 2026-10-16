<?php
if (empty($_SESSION['user'])) {
    header('Location: /login.php');
    exit;
}
if (!$ok) {
    header("location: /denied.php");
    die();
}
if (!$x) { header('Location: /y'); exit(); }
echo "welcome";
