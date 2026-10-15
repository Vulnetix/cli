package com.example.shop.web;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/orders")
public class OrderController {

    private final OrderService orders;

    public OrderController(OrderService orders) {
        this.orders = orders;
    }

    @PostMapping
    public OrderDto create(@Valid @RequestBody CreateOrderRequest req) {
        return orders.create(req);
    }

    @PutMapping("/{id}")
~>    public OrderDto update(@PathVariable long id, @RequestBody UpdateOrderRequest req) {
        return orders.update(id, req);
    }

    @PostMapping("/{id}/items")
    public OrderDto addItems(
            @PathVariable long id,
~>            @RequestBody final List<OrderItemRequest> items) {
        return orders.addItems(id, items);
    }

    @PostMapping("/{id}/notes")
    public void note(@PathVariable long id, @RequestBody String text) {
        orders.note(id, text);
    }
}
