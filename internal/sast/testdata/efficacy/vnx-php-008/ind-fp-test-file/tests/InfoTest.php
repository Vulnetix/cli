<?php
class InfoTest extends \PHPUnit\Framework\TestCase {
    public function testInfo() {
        ob_start();
        phpinfo();
        $this->assertNotEmpty(ob_get_clean());
    }
}
