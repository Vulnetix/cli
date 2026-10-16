<?php

$id = (int) $_GET['id'];
$r = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$n = mysqli_real_escape_string($conn, $_POST['n']);
$r2 = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $n . "'");
$r3 = mysqli_query($conn, 'SELECT COUNT(*) FROM users');
