<?php

namespace App;

class Importer
{
    public function importContacts(string $path): array
    {
        $rows = [];
        foreach (file($path . '/contacts.csv', FILE_IGNORE_NEW_LINES) as $line) {
            $fields = str_getcsv($line);
            $fields[3] = explode(",", $fields[3]);
            $rows[] = $fields;
        }
        return $rows;
    }
}
