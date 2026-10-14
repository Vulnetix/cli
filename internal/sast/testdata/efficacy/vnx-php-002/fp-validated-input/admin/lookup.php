<?php
$tool = $_GET["tool"];
$allowed = ["uptime", "df", "free"];
if (!in_array($tool, $allowed, true)) {
    exit("bad tool");
}
system($tool);

$ip = $_POST["ip"];
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    die("invalid");
}
exec("ping -c 1 " . $ip);
