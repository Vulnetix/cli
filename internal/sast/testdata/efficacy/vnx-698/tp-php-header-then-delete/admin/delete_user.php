<?php
session_start();
if (empty($_SESSION['is_admin']))
~>    header("Location: /login.php");

$id = (int) $_GET['id'];
$db->query("DELETE FROM users WHERE id = $id");
