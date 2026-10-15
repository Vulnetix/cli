<?php
if (isset($_POST['remember'])) {
~>    setcookie("password", $_POST['password'], time() + 86400 * 30, "/");
}
