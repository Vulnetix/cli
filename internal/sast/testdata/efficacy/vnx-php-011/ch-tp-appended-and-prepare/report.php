<?php
$sql = "SELECT * FROM orders WHERE 1=1";
$sql .= " AND customer = '" . $_POST['customer'] . "'";
~>$rows = $mysqli->query($sql);

$status = $_GET['status'];
~>$stmt = $pdo->prepare("SELECT * FROM orders WHERE status = '$status'");
$stmt->execute();
