<?php
$body = file_get_contents('php://input');
~>$reader = XMLReader::XML($body, 'UTF-8', LIBXML_NOENT);
$d = new DOMDocument();
~>$d->load($_FILES['f']['tmp_name'], LIBXML_DTDLOAD | LIBXML_NOENT);
