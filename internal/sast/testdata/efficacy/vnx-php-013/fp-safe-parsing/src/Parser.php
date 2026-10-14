<?php

libxml_disable_entity_loader(true);
$doc = simplexml_load_string($xml);
$doc2 = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA);
$dom = new DOMDocument();
$dom->substituteEntities = false;
$dom->resolveExternals = false;
$dom->loadXML($xml, LIBXML_NONET);
$reader = new XMLReader();
$reader->setParserProperty(XMLReader::SUBST_ENTITIES, false);
$el = new SimpleXMLElement($xml, LIBXML_NOERROR | LIBXML_NOWARNING);
