<?php

namespace App\Providers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
~>        Model::unguard();
~>        \Illuminate\Database\Eloquent\Model::unguard(true);
~>        Eloquent::unguard();
    }
}
