<?php

namespace Tests\Feature;

use App\Http\Middleware\VerifyCsrfToken;
use Tests\TestCase;

class TransferTest extends TestCase
{
    public function test_transfer(): void
    {
        $this->withoutMiddleware(VerifyCsrfToken::class);
        $this->post('/account/transfer', ['amount' => 5])->assertOk();
    }
}
