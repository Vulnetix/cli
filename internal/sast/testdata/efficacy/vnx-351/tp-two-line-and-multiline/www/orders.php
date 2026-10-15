<?php
function cancel(array $ownedIds) {
    $id = $_POST['id'];
~>    if (!in_array($id, $ownedIds)) {
        http_response_code(403);
        exit;
    }
~>    $pos = array_search(
        $_REQUEST['key'],
        $ownedIds
    );
}
