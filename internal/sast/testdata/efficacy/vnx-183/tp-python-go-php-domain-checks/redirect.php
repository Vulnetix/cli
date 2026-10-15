<?php

$redirect = $_GET['redirect'];
~>if (strpos($redirect, 'acme.com') !== false) {
    header('Location: ' . $redirect);
    exit;
}
~>if (str_ends_with($_SERVER['HTTP_HOST'] ?? '', 'acme.com') || str_contains($redirect, "acme.com")) {
    header('Location: ' . $redirect);
}
