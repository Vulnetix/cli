package com.shop.web;

@RestController
public class OrderController {
    private final OrderService orders;

    @GetMapping("/orders/{id}")
    public Order show(@PathVariable long id) {
        return orders.find(id);
    }

    @GetMapping("/orders")
    public List<Order> list() {
        return orderRepository.findAll();
    }
}
