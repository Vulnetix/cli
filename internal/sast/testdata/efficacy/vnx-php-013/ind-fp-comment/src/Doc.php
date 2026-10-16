<?php

// Do not use simplexml_load_string($x, 'SimpleXMLElement', LIBXML_NOENT) on untrusted XML.
$help = "libxml_disable_entity_loader(false) is dangerous";
$dom = new DOMDocument();
$dom->substituteEntities = false;
