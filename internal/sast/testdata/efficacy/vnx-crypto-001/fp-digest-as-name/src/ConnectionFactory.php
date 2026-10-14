<?php

class ConnectionFactory
{
    public function dynamicName(array $config)
    {
        return 'dynamic_'.md5(serialize($config));
    }

    public function compiledPath($view)
    {
        return $this->cachePath.'/'.md5($view).'.php';
    }

    public function tagKey($namespace, $key)
    {
        return md5($namespace).':'.$key;
    }
}
