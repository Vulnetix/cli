<?php
class Diagnostics
{
    public function capture()
    {
        file_put_contents('/var/log/app/server.txt', print_r($_SERVER, true));
        $this->logger->debug('session', ['dump' => var_export($_SESSION, true)]);
        error_log(print_r($_COOKIE, true));
    }
}
