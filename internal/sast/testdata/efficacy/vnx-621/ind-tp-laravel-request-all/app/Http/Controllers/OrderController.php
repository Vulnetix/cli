<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\Request;

class OrderController extends Controller
{
    public function store(Request $request)
    {
        $discount = 0;
~>        extract($request->all());

        return Order::create([
            'sku' => $sku,
            'quantity' => $quantity,
            'discount' => $discount,
        ]);
    }
}
