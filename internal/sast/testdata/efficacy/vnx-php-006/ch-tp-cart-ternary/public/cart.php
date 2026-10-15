<?php
$raw = $_COOKIE['cart'] ?? '';
~>$cart = $raw !== '' ? unserialize($raw) : [];
