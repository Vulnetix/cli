<?php
// Reported by VNX-784 (a security decision on a cookie), not by this rule.
$level = filter_input(INPUT_COOKIE, 'access_level', FILTER_SANITIZE_NUMBER_INT);
if ($level >= 5) {
    include __DIR__ . '/../views/panel.php';
} else {
    http_response_code(403);
}
