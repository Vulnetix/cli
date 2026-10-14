<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model
{
~>    protected $guarded = array();
}

class Invoice extends Model
{
~>    public $guarded = [ ];
}

class Refund extends Model
{
~>    protected $guarded = [
    ];
}
