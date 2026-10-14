<?php

$id = (int) $_GET['id'];
$res = mysqli_query($conn, "SELECT * FROM items WHERE id = $id");

$page = intval($_GET['page']);
$rows = mysqli_query($conn, "SELECT * FROM items LIMIT 10 OFFSET " . ($page * 10));

$name = $_POST['name'];
$name = mysqli_real_escape_string($conn, $name);
$r = mysqli_query($conn, "SELECT * FROM items WHERE name = '$name'");

$q = $pdo->query('SELECT * FROM items WHERE owner = ' . $pdo->quote($_POST['owner']));
