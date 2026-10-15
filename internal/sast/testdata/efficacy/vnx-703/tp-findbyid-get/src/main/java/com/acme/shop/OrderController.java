package com.acme.shop;

import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {
    private final OrderRepository orders;

    OrderController(OrderRepository orders) { this.orders = orders; }

    @GetMapping("/orders/{id}")
    public Order get(@PathVariable Long id) {
~>        return orders.findById(id).get();
    }

    @DeleteMapping("/orders/{id}")
    public void delete(@PathVariable Long id) {
~>        Order o = orders.findById(Long.valueOf(id)).get();
        orders.delete(o);
    }

    public String owner(Long id) {
~>        return Optional.ofNullable(cache.lookup(id)).get().getOwner();
    }
}
