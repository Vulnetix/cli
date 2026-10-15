<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    use Notifiable;

~>    protected array $guarded = [];

    protected $hidden = ['password', 'remember_token'];
}
