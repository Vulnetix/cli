<?php

if (!preg_match('/^\d+$/', $_GET['user_id'])) {
    exit('bad id');
}
$id = $_GET['user_id'];
$res = mysqli_query($conn, "SELECT * FROM users WHERE user_id = '$id'");

$page = $_GET['page'];
if (!ctype_digit($page)) {
    $page = '1';
}
$rows = mysqli_query($conn, "SELECT * FROM items LIMIT 10 OFFSET $page");
