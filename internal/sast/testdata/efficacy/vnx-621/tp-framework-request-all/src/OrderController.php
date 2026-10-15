<?php
class OrderController extends Controller
{
    public function store(Request $request)
    {
~>        extract($request->all());
        return Order::create(['item' => $item, 'paid' => $paid]);
    }

    public function update()
    {
~>        extract($this->input->post());
    }
}
