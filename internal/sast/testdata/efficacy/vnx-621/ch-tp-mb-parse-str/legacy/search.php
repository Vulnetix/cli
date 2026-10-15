<?php
$raw = $_SERVER['QUERY_STRING'];
~>mb_parse_str($raw);
$results = search_catalog($term, $page);
