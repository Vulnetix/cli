<?php
if (!isset($_SESSION['uid'])) {
    header("Location: login.php");
    die("Redirecting");
}
header("Content-Type: text/html; charset=utf-8");
echo "welcome";
