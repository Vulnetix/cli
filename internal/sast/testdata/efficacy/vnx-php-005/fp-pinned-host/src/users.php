<?php
$id = $_GET["id"];
$json = file_get_contents("https://api.example.com/users/" . urlencode($id));
$ch = curl_init("https://billing.example.com/v1/invoices/" . $_GET["invoice"]);
curl_setopt($ch, CURLOPT_URL, "https://billing.example.com/v1/" . $id);
$body = file_get_contents("php://input");
$data = json_decode(file_get_contents("php://input"), true);
