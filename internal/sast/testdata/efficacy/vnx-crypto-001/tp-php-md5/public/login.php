<?php
require_once 'db.php';

$user = $_POST['username'];
$pass = $_POST['password'];
~>$pass = md5( $pass );

$stmt = $db->prepare('SELECT * FROM users WHERE user = ? AND password = ?');
$stmt->execute([$user, $pass]);

~>$_SESSION['session_token'] = md5(uniqid());

~>$checksum = md5_file($_FILES['upload']['tmp_name']);

~>$cookie = hash('md5', $user . time());

~>$legacy = \MD5($pass);

function remember_token($id) {
~>    return hash_file("md5", "/tmp/sessions/" . $id);
}
