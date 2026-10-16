<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Seeder;

class UserSeeder extends Seeder
{
    public function run(): void
    {
        Model::unguard();
        User::create(['name' => 'admin', 'is_admin' => true]);
        Model::reguard();
    }
}
