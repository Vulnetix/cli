<?php

namespace App\Console\Commands;

use App\Models\Product;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;

class ImportProducts extends Command
{
    protected $signature = 'products:import {file}';

    public function handle(): int
    {
        $rows = json_decode(file_get_contents($this->argument('file')), true);

        Model::unguarded(function () use ($rows) {
            foreach ($rows as $row) {
                Product::create($row);
            }
        });

        Model::unguard();
        Product::upsert($rows, ['sku']);
        Model::reguard();

        return self::SUCCESS;
    }
}
