<?php
require 'db.php';

$name = $_POST['name'];
~>$stored = base64_encode($_POST['password']);
$db->query("INSERT INTO users (name, pw) VALUES (?, ?)", [$name, $stored]);

function obscure_password($password) {
~>    return str_rot13($password);
}
