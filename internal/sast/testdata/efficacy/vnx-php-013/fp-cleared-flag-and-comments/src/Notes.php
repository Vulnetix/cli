<?php

// simplexml_load_string($x, null, LIBXML_NOENT) enables XXE
/* $dom->loadXML($x, LIBXML_DTDLOAD); */
$flags = LIBXML_COMPACT & ~LIBXML_NOENT;
$doc = simplexml_load_string($xml, 'SimpleXMLElement', $flags);
$msg = 'do not pass LIBXML_NOENT to simplexml_load_string()';
$constName = 'LIBXML_NOENT';
