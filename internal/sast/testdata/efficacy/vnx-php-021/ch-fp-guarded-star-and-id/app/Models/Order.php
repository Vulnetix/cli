<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Order extends Model
{
    protected $guarded = ['id', 'is_paid', 'total'];
}

class AuditEntry extends Model
{
    protected $guarded = ['*'];

    public static function hasNoGuard(): bool
    {
        return (new static)->guarded === [];
    }
}
