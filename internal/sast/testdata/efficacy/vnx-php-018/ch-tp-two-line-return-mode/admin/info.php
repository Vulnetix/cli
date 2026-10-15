<?php
$out = print_r($_SESSION, true);
~>echo nl2br($out);
~>dd($_SERVER);
