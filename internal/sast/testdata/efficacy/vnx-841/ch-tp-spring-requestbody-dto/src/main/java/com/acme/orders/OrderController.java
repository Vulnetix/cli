package com.acme.orders;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    private final OrderRepository orders;

    public OrderController(OrderRepository orders) {
        this.orders = orders;
    }

    @PutMapping("/orders/{id}/status")
    public Order update(@PathVariable long id, @RequestBody StatusUpdate body) {
        Order order = orders.findById(id).orElseThrow();
~>        order.setStatus(body.getStatus());
        return orders.save(order);
    }
}
