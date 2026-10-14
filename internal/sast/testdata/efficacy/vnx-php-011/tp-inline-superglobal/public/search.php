<?php

$conn = mysqli_connect('localhost', 'app', getenv('DB_PASS'), 'shop');

~>$res = mysqli_query($conn, "SELECT * FROM products WHERE name LIKE '%" . $_GET['q'] . "%'");

~>mysql_query("DELETE FROM carts WHERE id = {$_POST['cart']}");

~>$r = mysqli_query($conn,
    "UPDATE users SET bio = '" . $_REQUEST['bio'] . "' WHERE id = 1");
