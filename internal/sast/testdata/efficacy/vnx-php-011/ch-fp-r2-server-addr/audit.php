<?php
$addr = $_SERVER['REMOTE_ADDR'];
$db->query("INSERT INTO audit (ip, at) VALUES ('" . $addr . "', NOW())");
mysqli_query($conn, "INSERT INTO hits (page) VALUES ('" . $_SERVER['SCRIPT_NAME'] . "')");
