<?php

class Loader
{
    public function boot($models, $zip, $xml)
    {
        $models->load('owner');
        $zip->open($this->path, ZipArchive::CREATE);
        $doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);
        $this->substituteEntities = $this->config['entities'] ?? false;
        $flags = [
            'noent' => 'LIBXML_NOENT',
        ];
        return [$doc, $flags];
    }
}
