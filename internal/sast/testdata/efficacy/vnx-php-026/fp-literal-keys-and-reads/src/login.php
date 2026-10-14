<?php
session_start();

$user = authenticate($_POST['username'], $_POST['password']);
if ($user) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user->id;
    $_SESSION['role'] = $user->role;
    $_SESSION['last_query'] = $_GET['q'];
    $_SESSION[SESSION_THEME] = $_POST['theme'];
}

$k = $_GET['k'];
$shown = $_SESSION[$k] ?? null;
if ($_SESSION[$_GET['k']] == 'x') {
    echo 'match';
}
$id = (int) $_GET['id'];
$_SESSION['ids'][] = $id;

$slot = 'cart';
$_SESSION[$slot] = [];
