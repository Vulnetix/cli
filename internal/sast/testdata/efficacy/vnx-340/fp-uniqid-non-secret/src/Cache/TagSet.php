<?php

class TagSet
{
    public function reset($name)
    {
        $this->store->forever($this->tagKey($name), $id = str_replace('.', '', uniqid('', true)));
        $directory = sys_get_temp_dir().'/views-'.uniqid();
        $token = bin2hex(random_bytes(16)) . uniqid();
        return $id;
    }
}
