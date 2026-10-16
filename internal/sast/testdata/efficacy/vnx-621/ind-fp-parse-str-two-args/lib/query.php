<?php
parse_str($_SERVER['QUERY_STRING'], $params);
$page = (int)($params['page'] ?? 1);
$csv = $this->extractor->extract($_POST);
$x = Extractor::extract($input);
$sql = "SELECT JSON_EXTRACT(doc, '$.name') FROM t";
// extract($_POST);  disabled
$msg = "do not call extract($_GET) anywhere";
