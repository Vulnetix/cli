<?php

global $wpdb;
$term = $_REQUEST['term'];
~>$rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}items WHERE title LIKE '%" . $term . "%'");
