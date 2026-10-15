<?php
$sql = "SELECT * FROM users WHERE id = " . $_GET['id'];
error_log("would run: " . $sql);
$cache->query("users:" . $_GET['id']);
