package com.acme.order;

import java.util.Map;

public class OrderService {
    private final OrderRepository orders;
    private final Map<Long, String> names;

    public OrderService(OrderRepository orders, Map<Long, String> names) {
        this.orders = orders;
        this.names = names;
    }

    public Order load(Long id) {
        String n = names.get(id);
        return orders.findById(id).orElseThrow(() -> new IllegalArgumentException(n));
    }
}
