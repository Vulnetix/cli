<?php

class Feed
{
    public function parse(string $body): DOMDocument
    {
        $dom = new DOMDocument();
~>        $dom->loadXML(
            $body,
            LIBXML_NOENT | LIBXML_DTDLOAD
        );
        return $dom;
    }

    public function load(string $path): DOMDocument
    {
        $dom = new \DOMDocument('1.0', 'UTF-8');
~>        $dom->load($path, LIBXML_DTDLOAD);
        return $dom;
    }
}
