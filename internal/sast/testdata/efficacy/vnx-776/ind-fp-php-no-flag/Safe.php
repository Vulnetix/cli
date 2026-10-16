<?php
function loadFeed(string $xml): DOMDocument {
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NONET);
    return $doc;
}
// LIBXML_PARSEHUGE is documented in the manual
