<?php
function read($xml) {
    $doc = new DOMDocument();
~>    $doc->loadXML($xml, LIBXML_DTDLOAD | LIBXML_NOENT);
    return $doc;
}
function reader($xml) {
    $r = new XMLReader();
    $r->xml($xml);
~>    $r->setParserProperty(XMLReader::LOADDTD, true);
}
