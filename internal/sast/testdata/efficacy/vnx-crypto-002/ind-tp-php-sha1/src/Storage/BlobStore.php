<?php

class BlobStore
{
    public function put(string $contents): string
    {
~>        $id = sha1($contents);
        file_put_contents($this->root . '/' . substr($id, 0, 2) . '/' . $id, $contents);
        return $id;
    }
}
