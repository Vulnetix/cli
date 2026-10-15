<?php

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (!isset($_SESSION['next_session_id'])) {
		$_SESSION['next_session_id'] = 1000;
	}
~>	$_SESSION['next_session_id']++;
	setcookie("appSession", $_SESSION['next_session_id']);
}

function issue_reset_code($db) {
	$last = $db->lastResetCode();
~>	$reset_code = $last + 1;
	return $reset_code;
}

function bump_invite($counter) {
~>	$invite_token = ++$counter;
	return $invite_token;
}
