<?php
parse_str($_SERVER['QUERY_STRING'], $query);
parse_str(parse_url($url, PHP_URL_QUERY) ?? '', $params);
mb_parse_str($_POST['q'], $out);
$msg = "never call extract($_POST) here";
