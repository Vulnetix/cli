<?php
~>$ch = curl_init($_POST['image_url']);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$img = curl_exec($ch);
