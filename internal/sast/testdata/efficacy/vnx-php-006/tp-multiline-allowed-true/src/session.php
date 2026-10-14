<?php
$token = $_SERVER["HTTP_X_SESSION"];
~>$session = unserialize(
    base64_decode($token),
    ["allowed_classes" => true]
);
