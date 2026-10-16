<?php
$c = htmlspecialchars($_REQUEST['title'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
$title = "<title>$c</title>";

$name = htmlspecialchars($_POST['name'], ENT_XML1, 'UTF-8');
$xml = "<user><name>" . $name . "</name></user>";

$doc = simplexml_load_string("<feed>" . $title . $xml . "</feed>");
echo $doc->asXML();
