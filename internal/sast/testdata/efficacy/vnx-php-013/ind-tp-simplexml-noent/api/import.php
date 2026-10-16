<?php

$xml = file_get_contents('php://input');
~>$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
echo $doc->name;
