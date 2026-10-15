<?php
class ViteTest extends TestCase
{
    public function testHotScript()
    {
        $this->assertSame('<script src="http://assets.example.com/app.js"></script>', $html);
    }
}
