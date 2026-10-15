<?php
if (empty($_SESSION['user'])) {
    header("Location: /login.php");
    exit;
}
if (empty($_SESSION['admin'])) {
    header('Location: /denied.php'); die();
}
if ($expired) {
    header("Location: /expired.php");
    // stop here
    exit();
}
function go_home() {
    header("Location: /");
    return;
}
header("Location: /done.php");
throw new RedirectException();
