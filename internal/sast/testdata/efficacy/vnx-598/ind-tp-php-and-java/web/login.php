<?php
$password = $_POST['pw'];
~>$url = "https://svc.example.com/auth?password=$password";
$r = file_get_contents($url);
