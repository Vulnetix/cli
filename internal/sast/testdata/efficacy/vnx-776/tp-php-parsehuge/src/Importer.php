<?php

class Importer
{
    public function fromUpload(string $xml): \DOMDocument
    {
        $dom = new \DOMDocument();
~>        $dom->loadXML($xml, LIBXML_PARSEHUGE | LIBXML_NONET);
        return $dom;
    }

    public function simple(string $xml)
    {
~>        return simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_PARSEHUGE);
    }
}
