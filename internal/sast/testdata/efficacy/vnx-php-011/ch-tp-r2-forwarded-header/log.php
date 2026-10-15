<?php
$ip = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : 'unknown';
$log_query = "INSERT INTO access_log (ip, agent) VALUES
              ('{$ip}', '" . $_SERVER['HTTP_USER_AGENT'] . "')";
~>mysqli_query($conn, $log_query);
