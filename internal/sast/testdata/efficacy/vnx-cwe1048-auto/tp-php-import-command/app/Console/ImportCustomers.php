<?php

namespace App\Console;

use App\Models\Customer;
use App\Services\Geocoder;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class ImportCustomers extends Command
{
    protected $signature = 'customers:import {file}';

    public function __construct(private Geocoder $geocoder)
    {
        parent::__construct();
    }

~>    public function handle(): int
    {
        $path = $this->argument('file');
        if (! Storage::disk('imports')->exists($path)) {
            $this->error("No such file: {$path}");
            return self::FAILURE;
        }
        $stream = Storage::disk('imports')->readStream($path);
        $header = fgetcsv($stream);
        $columns = array_map('strtolower', array_map('trim', $header));
        $this->info(sprintf('Importing %s', basename($path)));
        $bar = $this->output->createProgressBar();
        $bar->start();
        $imported = 0;
        $skipped = [];

        DB::beginTransaction();
        try {
            while (($row = fgetcsv($stream)) !== false) {
                $record = array_combine($columns, $row);
                $email = filter_var(trim($record['email'] ?? ''), FILTER_VALIDATE_EMAIL);
                if ($email === false) {
                    $skipped[] = $record;
                    continue;
                }
                $customer = Customer::firstOrNew(['email' => mb_strtolower($email)]);
                $customer->fill([
                    'name' => ucwords(strip_tags($record['name'])),
                    'phone' => preg_replace('/[^0-9+]/', '', $record['phone']),
                    'country' => strtoupper(substr($record['country'], 0, 2)),
                ]);
                $location = $this->geocoder->lookup($record['postcode'], $customer->country);
                if ($location !== null) {
                    $customer->latitude = round($location->lat(), 6);
                    $customer->longitude = round($location->lng(), 6);
                }
                $customer->tags()->sync(explode('|', $record['tags'] ?? ''));
                $customer->save();
                $imported++;
                $bar->advance();
            }
            DB::commit();
        } catch (\Throwable $e) {
            DB::rollBack();
            Log::error('customer import failed', ['file' => $path, 'error' => $e->getMessage()]);
            report($e);
            return self::FAILURE;
        } finally {
            fclose($stream);
        }

        $bar->finish();
        $this->newLine();
        if (count($skipped) > 0) {
            Storage::disk('imports')->put($path . '.rejected.json', json_encode($skipped, JSON_PRETTY_PRINT));
            $this->warn(count($skipped) . ' rows were rejected');
        }
        Log::info('customer import finished', compact('imported'));
        event(new \App\Events\CustomersImported($imported, now()));
        $this->table(['imported', 'rejected'], [[number_format($imported), count($skipped)]]);
        cache()->forget('customers.count');
        return self::SUCCESS;
    }
}
