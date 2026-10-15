<?php
function make_token($user, $secret) {
~>    return hash("sha1", $user . $secret);
}
