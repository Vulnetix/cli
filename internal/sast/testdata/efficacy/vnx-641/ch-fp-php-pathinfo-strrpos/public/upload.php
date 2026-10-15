<?php
$name = $_FILES['doc']['name'];
$ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
$ext2 = substr($name, strrpos($name, '.') + 1);
if (!preg_match('/\.(pdf|docx)$/i', $name)) {
    exit;
}
$parts = explode('.', $version)[1];
