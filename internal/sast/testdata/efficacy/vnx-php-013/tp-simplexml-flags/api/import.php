<?php

$xml = file_get_contents('php://input');
~>$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
~>$cfg = simplexml_load_file($_FILES['cfg']['tmp_name'], null, LIBXML_DTDLOAD | LIBXML_NOENT);
~>$el = new SimpleXMLElement($xml, LIBXML_NOENT);
