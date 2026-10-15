<?php
~>$xml = "<user><name>" . $_POST['name'] . "</name></user>";
$doc = simplexml_load_string($xml);

~>$comment = "<comment>{$_GET['c']}</comment>";
$c = $_REQUEST['title'];
~>$title = "<title>$c</title>";
$dom = new DOMDocument();
$dom->loadXML($comment . $title);
