<?php
$pw = $_POST['password'];
~>$stored = md5($salt . $pw . $pepper);
~>$user->pass_hash = md5(md5($_POST['passwd']));
~>$row['password'] = strtoupper(sha1($request->password));
~>$h = hash('sha1', $salt . $password);
