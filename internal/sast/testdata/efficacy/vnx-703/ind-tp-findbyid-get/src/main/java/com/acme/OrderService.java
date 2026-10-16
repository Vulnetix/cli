package com.acme;

public class OrderService {
    private final OrderRepository orders;
    OrderService(OrderRepository orders) { this.orders = orders; }

    public Order load(Long id) {
~>        return orders.findById(id).get();
    }
}
