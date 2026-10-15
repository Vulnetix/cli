package com.example.web;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/orders")
public class OrderController {

    @GetMapping("/{id}")
    public Order get(@PathVariable long id) {
        return toDto(repo.find(id));
    }

    @Deprecated
    private Order toDto(OrderEntity e) {
        return new Order(e.getId(), e.getTotal());
    }
}
