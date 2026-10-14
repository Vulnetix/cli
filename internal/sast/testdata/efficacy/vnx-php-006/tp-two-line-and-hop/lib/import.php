<?php
$payload = $_POST["data"];
~>$obj = unserialize($payload);

$raw = file_get_contents("php://input");
$decoded = gzuncompress($raw);
~>$job = unserialize($decoded);
