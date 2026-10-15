<?php
$dom = new DOMDocument();
~>$dom->resolveExternals = TRUE;
~>$dom->substituteEntities = True;
$dom->load($uploaded);
~>libxml_disable_entity_loader(FALSE);
