package com.acme.order;

public class OrderController {
    private final OrderRepository orders;

    public OrderController(OrderRepository orders) {
        this.orders = orders;
    }

    public Order show(Long id) {
~>        Order o = orders.findById(id).get();
        return o;
    }
}
