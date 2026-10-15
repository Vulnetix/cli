<?php
if (check_login($_POST['user'], $_POST['pass'])) {
~>    setcookie("admin", "1", time() + 3600, "/");
    header("Location: /");
}
