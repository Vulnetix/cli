<?php
function basic_token($username, $password) {
    return base64_encode("$username:$password");
}
