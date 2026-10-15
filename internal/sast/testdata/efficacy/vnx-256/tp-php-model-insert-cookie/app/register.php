<?php
$user = new User();
~>$user->password = $_POST['password'];
$user->save();
$pass = $_POST['pass'];
~>$stmt = $db->prepare("INSERT INTO users (email, password) VALUES ('$email', '$pass')");
~>setcookie("password", $_POST['password'], time() + 3600);
