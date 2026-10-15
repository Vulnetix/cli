package com.acme.shop;

public class OrderController {
    public Order get(Long id) {
        return orders.findById(id).orElseThrow(() -> new NotFoundException(id));
    }

    public Order first(java.util.List<Order> list) {
        return list.stream().findFirst().orElse(null);
    }

    public int top(java.util.List<Order> list) {
        return list.stream().mapToInt(Order::qty).max().orElse(0);
    }

    public void touch(Long id) {
        orders.findById(id).ifPresent(Order::touch);
    }
}
