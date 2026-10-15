<?php
$term = $_GET['q'];
error_log("search query: SELECT for " . $term);
$message = "No results for $term";
$res = $db->query("SELECT * FROM popular ORDER BY hits DESC LIMIT 10");
