<?php
extract($_POST, EXTR_PREFIX_ALL, 'in');
parse_str($_SERVER['QUERY_STRING'], $query);

$from = $query['from'] ?? date('Y-m-01');
$title = $in_title ?? 'Report';
echo htmlspecialchars($title . ' since ' . $from);
