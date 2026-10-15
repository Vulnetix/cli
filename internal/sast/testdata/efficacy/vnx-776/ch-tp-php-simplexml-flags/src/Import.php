<?php
function importCatalog(string $xml)
{
~>    $doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA | LIBXML_PARSEHUGE);
    return $doc->product;
}
