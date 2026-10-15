<?php
class Soap
{
    public function parse($data)
    {
        $dom = new \DOMDocument();
~>        $dom->substituteEntities = true;
        $dom->loadXML($data);
        $opts = LIBXML_NOENT | LIBXML_NONET;
        $other = new \DOMDocument();
~>        $other->loadXML($data, $opts);
        return [$dom, $other];
    }
}
