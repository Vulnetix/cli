<?php
$c = $_REQUEST['title'];

~>$xml = "<user><name>" . $_POST['name'] . "</name></user>";
~>$title = "<title>$c</title>";

$doc = simplexml_load_string("<feed>" . $title . "</feed>");
header('Content-Type: application/xml');
echo $doc->asXML();
