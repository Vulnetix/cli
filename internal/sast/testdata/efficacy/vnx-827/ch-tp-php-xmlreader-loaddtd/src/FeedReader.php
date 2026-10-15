<?php

class FeedReader
{
    public function open(string $path): \XMLReader
    {
        $reader = new \XMLReader();
        $reader->open($path);
~>        $reader->setParserProperty(\XMLReader::LOADDTD, true);
~>        $reader->setParserProperty(XMLReader::VALIDATE, true);
        return $reader;
    }

    public function load(string $xml)
    {
~>        return simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_DTDATTR | LIBXML_NOCDATA);
    }
}
