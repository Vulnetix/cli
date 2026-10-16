<?php
$q = $_POST['q'];
$today = date('Y-m-d');
$messages = [
    ['role' => 'system', 'content' => "You are a support bot. Today is {$today}."],
    ['role' => 'user', 'content' => $q],
];
// ['role' => 'system', 'content' => "You are $_GET[persona]"],
