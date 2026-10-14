<?php
function plugin_after_save() {
    $to = $_POST["redirect_to"];
~>    wp_redirect( $to );
    exit;
}

function psr7_handler($request, $response) {
    $params = $request->getQueryParams();
~>    return $response->withHeader("Location", $_GET["r"])->withStatus(302);
}
