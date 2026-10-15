<?php
setcookie('password', '', time() - 3600);
setcookie("password", "");
setcookie('id', $_POST['id']);
