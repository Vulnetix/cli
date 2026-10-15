<?php
function issue($last_token) {
~>	$_SESSION['token'] = $last_token + mt_rand(1, 100);
}

function bump(&$token) {
~>	$token += random_int(1, 9);
}
