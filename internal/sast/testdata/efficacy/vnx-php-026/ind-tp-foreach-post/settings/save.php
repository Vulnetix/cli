<?php
session_start();
foreach ($_POST as $field => $value) {
~>    $_SESSION[$field] = $value;
}
header('Location: /settings');
