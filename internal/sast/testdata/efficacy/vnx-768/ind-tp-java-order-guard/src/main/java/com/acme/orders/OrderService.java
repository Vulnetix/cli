package com.acme.orders;

public class OrderService {
    private final OrderRepository repo;

    public OrderService(OrderRepository repo) {
        this.repo = repo;
    }

    public void ship(long id) {
        Order order = repo.find(id);
~>        if (order != null & order.isPaid()) {
            order.markShipped();
            repo.save(order);
        }
    }

    public boolean isBlank(String name) {
~>        return name == null | name.trim().isEmpty();
    }
}
