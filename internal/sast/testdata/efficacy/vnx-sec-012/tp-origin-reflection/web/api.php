<?php
$origin = $_SERVER['HTTP_ORIGIN'];
~>header("Access-Control-Allow-Origin: " . $origin);
header("Access-Control-Allow-Credentials: true");
