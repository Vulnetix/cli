<?php
$link = mysqli_connect(getenv('DB_HOST'), getenv('DB_USER'), getenv('DB_PASSWORD'), 'app');
$pdo = new PDO($dsn, $user, $password);
// mysqli_connect('localhost', 'root', 'Old-R00t-Pass') was removed in 2021
