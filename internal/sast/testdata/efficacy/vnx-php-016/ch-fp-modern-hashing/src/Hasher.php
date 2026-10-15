<?php
$hash = password_hash($password, PASSWORD_DEFAULT);
if (password_verify($password, $row['password'])) {
    $ok = true;
}
$etag = md5($content);
$cacheKey = sha1($url);
