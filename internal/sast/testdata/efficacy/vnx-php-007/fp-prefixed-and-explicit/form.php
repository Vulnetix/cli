<?php
extract($_POST, EXTR_PREFIX_ALL, "form");
$name = $_POST["name"] ?? "";
$email = filter_input(INPUT_POST, "email", FILTER_VALIDATE_EMAIL);
foreach ($_GET as $key => $value) {
    $filters[$key] = $value;
}
