<?php

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute([':id' => $_GET['id']]);
$s2 = $mysqli->prepare("SELECT * FROM t WHERE a = ?");
$s2->bind_param('s', $_POST['a']);
