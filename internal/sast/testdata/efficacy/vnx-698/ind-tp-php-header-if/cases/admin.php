<?php
session_start();
if (empty($_SESSION['is_admin']))
~>    header("Location: /login.php");
$db->query("DELETE FROM users WHERE id = " . intval($_GET['id']));
echo "deleted";
