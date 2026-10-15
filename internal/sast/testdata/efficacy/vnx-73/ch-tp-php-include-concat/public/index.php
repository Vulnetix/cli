<?php
~>include($_GET['page'] . '.php');

$f = $_REQUEST['f'];
~>readfile("files/" . $f);
