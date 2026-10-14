<?php

namespace App\Console\Commands;

use App\Models\Order;
use Illuminate\Database\Eloquent\Model;

class ImportLegacy extends Command
{
    public function handle()
    {
        Model::unguarded(function () {
            Order::create($this->legacyRow());
        });
        Model::unguard();
        Order::insertFromLegacy();
        Model::reguard();
    }
}
