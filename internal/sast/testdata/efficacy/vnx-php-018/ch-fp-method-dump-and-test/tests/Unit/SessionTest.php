<?php
class SessionTest extends TestCase
{
    public function testSession()
    {
        var_dump($_SESSION);
        $this->assertTrue(true);
    }
}
