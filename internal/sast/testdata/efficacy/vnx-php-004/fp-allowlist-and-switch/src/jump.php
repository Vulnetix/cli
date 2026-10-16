<?php
$allowed = ['/home', '/account', '/orders'];
$to = $_GET['to'];
if (!in_array($to, $allowed, true)) {
    $to = '/home';
}
header('Location: ' . $to);

$target = "";
switch (intval($_GET['redirect'])) {
    case 1:
        $target = "info.php?id=1";
        break;
    case 2:
        $target = "info.php?id=2";
        break;
}
if ($target != "") {
    header("location: " . $target);
}

$u = $_GET['u'];
if (parse_url($u, PHP_URL_HOST) !== null) {
    exit;
}
header('Location: ' . $u);
