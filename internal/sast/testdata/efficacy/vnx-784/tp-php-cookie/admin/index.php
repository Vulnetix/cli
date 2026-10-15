<?php
~>if ($_COOKIE['user_role'] === 'admin') {
    show_admin_tools();
}

~>$loggedIn = $_COOKIE["logged_in"] ?? "0";
if ($loggedIn == "1") {
    show_account();
}
