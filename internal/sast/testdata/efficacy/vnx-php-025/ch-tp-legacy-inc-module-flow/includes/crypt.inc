<?php
class LegacyCrypt
{
    private $key;

    public function __construct($key)
    {
        $this->key = $key;
    }

    public function seal($data)
    {
~>        $module = @mcrypt_module_open('tripledes', '', 'cbc', '');
~>        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($module), MCRYPT_DEV_URANDOM);
        mcrypt_generic_init($module, $this->key, $iv);
~>        $out = mcrypt_generic($module, $data);
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);
        return $iv . $out;
    }

    public function open($blob, $iv)
    {
~>        $module = mcrypt_module_open(MCRYPT_TRIPLEDES, '', MCRYPT_MODE_CBC, '');
        mcrypt_generic_init($module, $this->key, $iv);
~>        $plain = mdecrypt_generic($module, $blob);
        mcrypt_module_close($module);
        return $plain;
    }
}
