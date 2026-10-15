<?php

class Importer
{
    public function fromUpload(string $xml): \DOMDocument
    {
        $dom = new \DOMDocument();
        // LIBXML_PARSEHUGE is deliberately not passed here.
        $dom->loadXML($xml, LIBXML_NONET);
        return $dom;
    }
}
