<?php
~>$hash = md5($_POST['password']);
$db->insert('users', ['pw' => $hash]);
