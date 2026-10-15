<?php
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NONET | LIBXML_NOCDATA);
if (defined('LIBXML_NOENT')) {
    $flags = 0;
}
$sx = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA);
$doc->substituteEntities = false;
$doc->resolveExternals = false;
