<?php
global $wpdb;
$id = $_GET['report_id'];
$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}reports WHERE id = %d", $id));
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
$stmt->execute([$_POST['email']]);
$rows = $pdo->query('SELECT * FROM users WHERE id = ' . (int) $_GET['id']);
$q = $pdo->quote($_GET['name']);
$named = $pdo->query("SELECT * FROM users WHERE name = $q");
