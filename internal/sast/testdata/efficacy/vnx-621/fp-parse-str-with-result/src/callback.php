<?php
parse_str($_SERVER['QUERY_STRING'], $params);
$code = $params['code'] ?? null;

parse_str(
    $body,
    $fields
);
foreach ($_GET as $key => $value) {
    $clean[$key] = trim($value);
}
