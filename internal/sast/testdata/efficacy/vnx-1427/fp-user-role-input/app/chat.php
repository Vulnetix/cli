<?php
$question = $_POST['question'];
$messages = [
    ['role' => 'system', 'content' => 'You answer billing questions only.'],
    ['role' => 'user', 'content' => $question],
];
