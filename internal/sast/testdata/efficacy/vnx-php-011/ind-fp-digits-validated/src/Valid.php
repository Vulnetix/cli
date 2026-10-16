<?php

$page = $_GET['page'];
if (!ctype_digit($page)) { die('bad'); }
$r = mysqli_query($conn, "SELECT * FROM posts LIMIT 10 OFFSET " . $page);
