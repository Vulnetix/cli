<?php
$host = escapeshellarg($_POST["host"]);
$out = shell_exec("ping -c 3 " . $host);
echo "<pre>" . htmlspecialchars($out) . "</pre>";
exec("ls -la " . escapeshellarg($_GET["dir"]), $lines, $rc);
