<?php

$user = $_COOKIE['user'];
~>print "Welcome back, $user";
~>printf('<div class="msg">%s</div>', $_GET['msg']);
~>die('Unknown page: ' . $_GET['page']);
~>exit("Invalid token " . $_POST['token']);
