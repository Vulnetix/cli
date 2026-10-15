<?php
$ch = curl_init();
curl_setopt_array($ch, [
~>    CURLOPT_URL => $_POST['webhook'],
    CURLOPT_RETURNTRANSFER => true,
]);
~>curl_setopt_array($ch, [CURLOPT_URL => $_GET['ping'], CURLOPT_TIMEOUT => 5]);
$resp = curl_exec($ch);
