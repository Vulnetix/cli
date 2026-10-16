<?php

$hash = password_hash($_POST['password'], PASSWORD_ARGON2ID);
if (password_verify($_POST['password'], $hash)) { login(); }
