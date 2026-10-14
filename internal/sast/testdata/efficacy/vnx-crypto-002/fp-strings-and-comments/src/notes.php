<?php
// $stored = sha1($password); was replaced by password_hash()
$query = "SELECT id FROM users WHERE token = sha1(?)";
