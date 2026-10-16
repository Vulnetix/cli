<?php
session_start();
$user = authenticate($_POST['user'], $_POST['pass']);
$_SESSION['user_id'] = $user->id;
$_SESSION['role'] = $user->role;
$_SESSION['sort_' . $_GET['col']] = 'asc';
$_SESSION['filters'][$_GET['col']] = $_GET['val'];
