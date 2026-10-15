<?php
// Never write md5($p) == $stored, use hash_equals() instead.
/* $_POST['token'] == $secret is vulnerable to type juggling */
$msg = "md5(\$pw) == \$hash";
echo $msg;
