<?php
function import_feed(string $xml)
{
    $doc = new DOMDocument();
~>    $doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
    return $doc;
}
