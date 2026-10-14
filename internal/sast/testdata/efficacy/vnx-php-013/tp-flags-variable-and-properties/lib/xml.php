<?php

function parse_upload($data)
{
    $opts = LIBXML_NOENT | LIBXML_NONET;
~>    return simplexml_load_string($data, 'SimpleXMLElement', $opts);
}

function parse_dom($data)
{
    $dom = new DOMDocument();
~>    $dom->substituteEntities = true;
~>    $dom->resolveExternals = true;
    $dom->loadXML($data);
    return $dom;
}

function read_stream($uri)
{
    $reader = new XMLReader();
    $reader->open($uri);
~>    $reader->setParserProperty(XMLReader::SUBST_ENTITIES, true);
    return $reader;
}
