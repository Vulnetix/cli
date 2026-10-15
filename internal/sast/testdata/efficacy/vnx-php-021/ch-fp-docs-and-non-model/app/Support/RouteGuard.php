<?php

namespace App\Support;

class RouteGuard
{
    private array $guardedRoutes = [];

    public function guard(string $name): void
    {
        $this->guardedRoutes[] = $name;
    }

    public function message(): string
    {
        return 'Set protected $guarded = []; only in seeders';
    }
}
