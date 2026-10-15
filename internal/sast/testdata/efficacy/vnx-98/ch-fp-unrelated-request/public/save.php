<?php
include 'config.php';
require_once 'lib/db.php';

$name = $_POST['name'];
$db = connect();
include 'partials/header.php';
$stmt = $db->prepare('INSERT INTO people (name) VALUES (?)');
$stmt->execute([$name]);
// include $_GET['page']; was the old router
echo "Saved include $name";
