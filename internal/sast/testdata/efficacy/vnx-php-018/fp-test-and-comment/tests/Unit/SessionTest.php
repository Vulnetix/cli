<?php
class SessionTest extends TestCase
{
    public function testSession()
    {
        var_dump($_SESSION);
        print_r($_SERVER);
    }
}
