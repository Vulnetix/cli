<?php
function loadFeed(string $xml): DOMDocument {
    $doc = new DOMDocument();
~>    $doc->loadXML($xml, LIBXML_NOENT | LIBXML_PARSEHUGE);
    return $doc;
}
