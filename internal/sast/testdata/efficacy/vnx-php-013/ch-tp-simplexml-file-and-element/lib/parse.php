<?php
function parse_upload($path)
{
~>    return simplexml_load_file($path, 'SimpleXMLElement', LIBXML_NOENT);
}

function parse_body($body)
{
~>    return new SimpleXMLElement($body, LIBXML_NOENT);
}
