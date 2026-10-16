<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class WidgetFactory extends Factory
{
    protected $guarded = [];
    public function definition(): array { return ['name' => 'w']; }
}
