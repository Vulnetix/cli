<?php
$salt = 'k9';
~>if (sha1($salt . $_GET['code']) == "@@sample:0[e]46[2]09[7]43[1]90[6]50[9]01[9]56[2]98[8]73[6]85[4]@@") {
    grant();
}

$expected = load_api_key();
~>if (strcmp($_POST['token'], $expected) == 0) {
    grant();
}
