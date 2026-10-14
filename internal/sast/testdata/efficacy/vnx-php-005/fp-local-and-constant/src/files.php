<?php
$name = $_GET["name"];
$tpl = file_get_contents(__DIR__ . "/templates/" . $name);
$cfg = file_get_contents(CONFIG_DIR . $_GET["cfg"]);
$lines = file("data/" . $name . ".csv");
$fh = fopen(storage_path("logs/" . $name), "a");
$readme = file_get_contents("README.txt");
$remote = file_get_contents($config["feed_url"]);
function fetch_url($url) {
    return file_get_contents($url);
}
