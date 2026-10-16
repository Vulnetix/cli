<?php
// A hash compared loosely is reported by VNX-PHP-010.
$token = $_POST['token'];
if ($token == md5(str_rot13("success"))) {
    echo "ok";
}
