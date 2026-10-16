<?php

final class LegacySigner
{
    public function sign(string $body, string $key): string
    {
        // Older partners still expect hash_hmac with sha1.
        return hash_hmac('sha1', $body, $key);
    }
}
