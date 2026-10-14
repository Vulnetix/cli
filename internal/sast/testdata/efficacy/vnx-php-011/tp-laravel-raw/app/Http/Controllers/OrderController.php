<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class OrderController extends Controller
{
    public function index(Request $request)
    {
        $status = $request->input('status');
~>        $orders = DB::select("SELECT * FROM orders WHERE status = '$status'");

~>        return Order::whereRaw('customer = ' . $request->get('customer'))->get();
    }
}
