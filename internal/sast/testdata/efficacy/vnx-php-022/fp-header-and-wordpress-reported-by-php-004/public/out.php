<?php
// A raw Location header, wp_redirect() and a PSR-7 withHeader() fed from
// the request: VNX-PHP-004 reports these, so VNX-PHP-022 does not.
$next = $_GET['next'];
header('Location: ' . $next);
header("Location: {$_POST['to']}", true, 302);
header(
    'Location: ' . $_REQUEST['back']
);
wp_redirect($_REQUEST['redirect_to']);

function psr7($request, $response) {
    return $response->withHeader('Location', $_GET['r'])->withStatus(302);
}
