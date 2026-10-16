<?php
$raw = base64_decode($_COOKIE["state"]);
$sig = $_COOKIE["sig"];
if (!hash_equals(hash_hmac("sha256", $raw, $secret), $sig)) {
    exit;
}
$state = unserialize($raw);
