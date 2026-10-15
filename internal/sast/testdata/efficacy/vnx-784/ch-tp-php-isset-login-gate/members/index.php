<?php
~>if (!isset($_COOKIE['logged_in'])) {
    header('Location: /login.php');
    exit;
}
echo 'Members area';
