<?php
$name = htmlspecialchars($_POST['name'], ENT_XML1);
$xml = "<user><name>" . htmlspecialchars($_POST['name'], ENT_XML1) . "</name></user>";
$doc = simplexml_load_string($xml);
