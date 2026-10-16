<?php

$doc = simplexml_load_string($xml);
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NONET);
$r = new XMLReader();
$r->xml($xml, null, LIBXML_NOBLANKS);
libxml_disable_entity_loader(true);
