<?php

$title = 'Dashboard';
echo "<h1>$title</h1>";
echo 'Literal $_GET["name"] is not interpolated';
$name = $_GET['name'];
$query = "SELECT * FROM users WHERE name = ?";
echo $query;
print_r($config);
