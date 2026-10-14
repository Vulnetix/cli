<?php

class FilesystemTest
{
    public function testChmod(): void
    {
        @chmod($this->tempDir . '/foo.txt', 0777);
        mkdir($this->tempDir . '/tmp', 0777, true);
    }
}
