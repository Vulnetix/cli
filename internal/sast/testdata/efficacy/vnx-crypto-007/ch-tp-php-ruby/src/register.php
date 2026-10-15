<?php
~>$hash = sha1($_POST['password'] . $salt);
~>$h2 = hash('sha256', $pass);
~>$h3 = password_hash($pass, PASSWORD_BCRYPT, ['cost' => 4]);
