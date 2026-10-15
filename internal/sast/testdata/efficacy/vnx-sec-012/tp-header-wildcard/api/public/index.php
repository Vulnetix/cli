<?php
~>header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
echo json_encode(get_user_orders($_SESSION['uid']));
