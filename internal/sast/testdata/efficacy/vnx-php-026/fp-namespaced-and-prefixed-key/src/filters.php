<?php
session_start();

$col = $_GET['col'];
$_SESSION['filters'][$col] = $_GET['dir'];
$_SESSION['sort_' . $col] = 'asc';
$_SESSION["grid_{$col}"] = 1;

foreach ($_POST as $k => $v) {
    $_SESSION['form'][$k] = $v;
}

$_SESSION['form'] = array_merge($_SESSION['form'] ?? [], $_POST);
$_SESSION = array_merge($_SESSION, ['flash' => 'saved']);
