<?php
~>if ($_COOKIE['loggedin'] == 'true') {
    include 'dashboard.php';
} else {
    header('Location: /login.php');
}
