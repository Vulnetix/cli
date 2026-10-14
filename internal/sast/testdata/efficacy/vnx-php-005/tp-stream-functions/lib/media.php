<?php
$src = $_GET["image"];
~>$size = getimagesize($src);
~>$fp = fopen($_POST["remote"], "r");
~>$headers = get_headers($_GET["check"], true);
~>$doc = simplexml_load_file($_REQUEST["sitemap"]);
$host = $_GET["host"];
~>$sock = fsockopen($host, 80, $errno, $errstr, 5);
~>readfile($_GET["mirror"]);
