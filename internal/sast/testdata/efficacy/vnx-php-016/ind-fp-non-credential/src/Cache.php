<?php

$key = md5($url . $query);
header('ETag: "' . md5_file($path) . '"');
$sum = sha1($body);
$prefix = substr(strtoupper(sha1($candidate)), 0, 5);
$bypass = md5($request_uri);
