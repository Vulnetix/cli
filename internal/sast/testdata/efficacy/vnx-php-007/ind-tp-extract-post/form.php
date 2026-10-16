<?php
$isAdmin = false;
~>extract($_POST);
if ($isAdmin) { echo "admin"; }
