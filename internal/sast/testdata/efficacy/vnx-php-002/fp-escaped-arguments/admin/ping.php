<?php
$host = $_POST["host"];
$out = shell_exec("ping -c 3 " . escapeshellarg($host));
$safe = escapeshellarg($_GET["dir"]);
exec("ls -la " . $safe, $lines);
$n = (int) $_GET["count"];
system("seq 1 " . $n);
$port = intval($_REQUEST["port"]);
exec("nc -z localhost " . $port);
exec("file --mime-type " . $_FILES["doc"]["tmp_name"]);
