<?php

if (isset($_POST['Change']) && ($_POST['step'] == '1')) {
    step_one();
}

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    handle();
}

$page = $_GET['page'];
if ($page == $current) {
    highlight();
}

if (md5_file($path) == 'd41d8cd98f00b204e9800998ecf8427e') {
    empty_file();
}

if ($count == $limit) {
    stop();
}

$pass_new = $_GET['password_new'];
$pass_conf = $_GET['password_conf'];
if ($pass_new == $pass_conf) {
    change_password($pass_new);
}
