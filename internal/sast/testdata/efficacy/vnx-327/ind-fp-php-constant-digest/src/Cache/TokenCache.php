<?php

namespace App\Cache;

class TokenCache
{
    private function prefix(): string
    {
        return 'token_cache_' . sha1(static::class);
    }

    public function get(string $id)
    {
        return apcu_fetch($this->prefix() . $id);
    }
}
