<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Post extends Model
{
    protected $guarded = ['id', 'is_admin', 'user_id'];

    protected $fillable = ['title', 'body'];
}

class Tag extends Model
{
    protected $guarded = ['*'];
}
