<?php

$data = [
    'email' => $email,
~>    'password' => md5($raw . 'x'),
];
$db->insert('users', $data);
