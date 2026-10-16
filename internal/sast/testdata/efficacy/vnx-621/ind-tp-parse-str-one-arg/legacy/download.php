<?php
$base = '/srv/files/';
~>parse_str($_SERVER['QUERY_STRING']);
readfile($base . basename($file));
