<?php

// if ($_POST['password'] == $row['password']) was the old check
/* md5($plain) == $stored is vulnerable to magic hashes */
$help = 'never write md5($a) == $b in auth code';
$doc = "compare with === not == \$_POST['token']";
