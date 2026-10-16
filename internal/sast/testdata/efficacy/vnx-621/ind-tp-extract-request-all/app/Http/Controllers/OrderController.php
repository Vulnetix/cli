<?php
namespace App\Http\Controllers;

class OrderController extends Controller
{
    public function store(Request $request)
    {
        $price = Product::find($request->sku)->price;
~>        extract($request->all());
        return $this->charge($price, $qty);
    }
}
