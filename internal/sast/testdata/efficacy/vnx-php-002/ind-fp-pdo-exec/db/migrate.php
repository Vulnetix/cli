<?php
$pdo = new PDO($dsn, $user, $pass);
$pdo->exec("CREATE TABLE IF NOT EXISTS log (id INT)");
$stmt = $pdo->query("SELECT 1");
$id = $_GET["id"];
$pdo->exec("DELETE FROM log WHERE id = " . (int)$id);
