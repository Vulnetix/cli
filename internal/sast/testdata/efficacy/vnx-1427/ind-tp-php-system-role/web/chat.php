<?php
$persona = $_GET['persona'];
$messages = [
~>    ['role' => 'system', 'content' => "You are a {$persona} assistant."],
    ['role' => 'user', 'content' => 'Hello'],
];
