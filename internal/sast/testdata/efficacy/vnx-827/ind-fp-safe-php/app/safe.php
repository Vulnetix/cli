<?php
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NONET);
libxml_disable_entity_loader(true);
// $doc->loadXML($xml, LIBXML_DTDLOAD);
$msg = "LIBXML_DTDLOAD";
