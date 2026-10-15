<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    protected $table = 'invoices';

~>    public $guarded=[ ];

    public function customer()
    {
        return $this->belongsTo(Customer::class);
    }
}
