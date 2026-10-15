<?php
global $wpdb;
$id = $_GET['report_id'];
~>$row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}reports WHERE id = $id");
~>$all = $wpdb->get_results("SELECT * FROM wp_posts WHERE post_author = " . $_POST['author']);
