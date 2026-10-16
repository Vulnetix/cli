<?php
use PHPUnit\Framework\TestCase;

class EnvTest extends TestCase
{
    public function testEnvDump()
    {
        var_dump($_ENV);
        print_r($_SERVER);
    }
}
