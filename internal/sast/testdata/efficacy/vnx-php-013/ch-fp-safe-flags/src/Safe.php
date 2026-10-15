<?php
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NONET);
$s = simplexml_load_string($xml);
libxml_disable_entity_loader(true);
$doc->substituteEntities = false;
$doc->resolveExternals = false;
