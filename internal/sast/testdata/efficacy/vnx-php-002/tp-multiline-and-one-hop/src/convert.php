<?php
$name = trim($_POST["name"]);
$opts = "--quality 80 " . $name;
~>exec(
    "magick " . $opts,
    $output
);
$raw = file_get_contents("php://input");
~>system("jq . <<< " . $raw);
