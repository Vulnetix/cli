<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class CartController extends Controller
{
    public function add(Request $request)
    {
        $id = $request->input('id');
        session()->put('cart.last', $id);
        $request->session()->put('cart_count', 3);
        return back();
    }
}
