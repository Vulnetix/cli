<?php
$host = $_GET["h"];
~>$data = file_get_contents("http://" . $host . "/status");
~>$page = file_get_contents("https://{$_GET["domain"]}/robots.txt");
