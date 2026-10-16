<?php
$expr = $_REQUEST['expr'];
~>eval('$answer = ' . $expr . ';');
echo $answer;
