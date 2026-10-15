<?php

use Illuminate\Support\Facades\Route;

Route::get('/', fn () => view('welcome'));
~>Route::get('/phpinfo', fn () => phpinfo());
Route::get('/info', function () {
~>    phpinfo(INFO_MODULES);
});
