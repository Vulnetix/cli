<?php
class Sizes
{
    public function ivLength(): int
    {
        return mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    }

    public function keyLength(): int
    {
        return mcrypt_get_key_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    }

    public function close($td): void
    {
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
    }
}
