<?php

class Importer
{
    public function load(string $xml): DOMDocument
    {
        $dom = new DOMDocument();
~>        $dom->loadXML($xml, LIBXML_DTDLOAD | LIBXML_DTDATTR);
        return $dom;
    }

    public function simple(string $xml)
    {
~>        return simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDVALID);
    }

    public function externals(string $xml): DOMDocument
    {
        $dom = new DOMDocument();
~>        $dom->resolveExternals = true;
        $dom->loadXML($xml);
        return $dom;
    }
}
