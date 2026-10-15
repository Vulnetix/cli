<?php
~>$xml = "<user><id>{$_GET['id']}</id></user>";
$doc = simplexml_load_string($xml);
echo $doc->id;
