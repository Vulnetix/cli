<?php
class InfoTest extends TestCase
{
    public function testInfo()
    {
        ob_start();
        phpinfo();
        $this->assertNotEmpty(ob_get_clean());
    }
}
