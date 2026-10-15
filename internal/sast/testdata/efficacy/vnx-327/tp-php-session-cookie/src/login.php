<?php
~>$_SESSION['session_token'] = md5(uniqid());
~>$cookie_value = sha1($_SESSION['last_session_id']);
~>if ($token === md5_file($upload)) { echo "ok"; }
