<?php
$id = $_GET["id"];
$json = file_get_contents("https://api.example.com/users/" . urlencode($id));
$ch = curl_init("https://api.example.com/v1/items/" . (int)$id);
