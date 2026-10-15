<?php

function load_safe(string $xml): DOMDocument
{
    $dom = new DOMDocument();
    $dom->resolveExternals = false;
    $dom->loadXML($xml, LIBXML_NONET);
    // LIBXML_DTDLOAD would load the DTD; we never pass it
    return $dom;
}
