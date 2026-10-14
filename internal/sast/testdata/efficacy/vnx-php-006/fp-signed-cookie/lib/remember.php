<?php
$payload = $_COOKIE["remember"];
$sig = $_COOKIE["remember_sig"] ?? "";
if (!hash_equals(hash_hmac("sha256", $payload, APP_KEY), $sig)) {
    exit;
}
$user = unserialize($payload);
