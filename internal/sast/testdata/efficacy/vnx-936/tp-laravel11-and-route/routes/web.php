<?php

use App\Http\Controllers\TransferController;
use App\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => view('welcome'));

~>Route::post('/account/transfer', [TransferController::class, 'store'])->withoutMiddleware([VerifyCsrfToken::class]);

Route::post('/profile', [TransferController::class, 'profile'])
~>    ->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class);
