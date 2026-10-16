<?php
$is_admin = false;
$name = $_GET['var'];
~>$$name = $_GET['value'];
if ($is_admin) {
    echo "welcome admin";
}
