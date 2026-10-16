<?php

namespace App\Console;

use App\Models\Order;
use Illuminate\Database\Eloquent\Model;

class Import
{
    public function row(array $row)
    {
        Model::unguarded(fn () => Order::create($row));
    }
}
