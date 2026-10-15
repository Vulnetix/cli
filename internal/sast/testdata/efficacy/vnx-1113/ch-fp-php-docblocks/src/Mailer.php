<?php

/**
 * Sends mail.
 */
class Mailer
{
    /**
     * @param string $to recipient, see RFC 5322 3.4
     */
    public function send(string $to): void
    {
        $path = 'templates/*.twig'; /* loaded lazily */
    }
}
