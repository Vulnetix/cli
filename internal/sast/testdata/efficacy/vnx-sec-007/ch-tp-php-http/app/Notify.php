<?php
use Illuminate\Support\Facades\Http;

function notify(string $text): void
{
~>    Http::post('https://hooks.slack.com/workflows/T@@sample:[A-Z0-9]{9}@@/A@@sample:[A-Z0-9]{10}@@/@@sample:[0-9]{18}@@/@@sample:[A-Za-z0-9]{24}@@', ['text' => $text]);
}
