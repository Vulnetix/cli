<?php
namespace App;

class Import
{
    public function parse(string $xml)
    {
        $doc = new \DOMDocument();
~>        $doc->loadXML($xml, \LIBXML_NOENT | \LIBXML_DTDLOAD);
~>        $sx = new \SimpleXMLElement($xml, \LIBXML_NOENT);
        return [$doc, $sx];
    }
}
