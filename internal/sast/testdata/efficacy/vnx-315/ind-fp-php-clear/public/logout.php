<?php
setcookie('password', '', time() - 3600, '/');
setcookie('remember_me', '', time() - 3600, '/');
session_destroy();
header('Location: /login.php');
