<?php
$sql = sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%'", $_GET['q']);
~>$res = mysqli_query($link, $sql);
