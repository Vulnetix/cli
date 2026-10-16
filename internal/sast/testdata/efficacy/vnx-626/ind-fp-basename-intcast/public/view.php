<?php
$page = basename($_GET['page']);
include(__DIR__ . '/pages/' . $page . '.php');

$id = (int) $_GET['id'];
echo file_get_contents("invoices/{$id}.txt");
