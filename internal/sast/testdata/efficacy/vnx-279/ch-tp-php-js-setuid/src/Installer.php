<?php

final class Installer
{
    public function install(string $helper): void
    {
        copy(__DIR__ . '/../bin/helper', $helper);
~>        chmod($helper, 04755);
    }
}
