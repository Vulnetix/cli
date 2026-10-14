<?php
session_destroy();
$back = $_SERVER["HTTP_REFERER"];
~>header("Location: $back");
$next = $_GET["next"] ?? "/";
if (strpos($next, "example.com") !== false) {
~>    header("Location: " . $next);
}
$host = $_GET["host"];
~>header("Location: https://" . $host . "/welcome");
