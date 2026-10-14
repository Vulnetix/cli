<?php

define('CACHE_MODE', 0777);
define('CONFIG_MODE', 0640);

final class Bootstrap
{
    const UPLOAD_MODE = 0777;

    public static function prepare(string $cache, string $config, string $uploads): void
    {
        if (!is_dir($cache)) {
            mkdir($cache);
        }
~>        chmod($cache, CACHE_MODE);
        chmod($config, CONFIG_MODE);
~>        chmod($uploads, self::UPLOAD_MODE);
    }
}
