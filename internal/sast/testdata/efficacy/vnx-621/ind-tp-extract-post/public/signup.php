<?php
session_start();
$is_admin = false;
~>extract($_POST);
if ($is_admin) {
    echo "welcome admin";
}
