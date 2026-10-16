package com.shop.web;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/orders")
~>@CrossOrigin
public class OrderController {

    @GetMapping("/{id}")
    public Order get(@PathVariable String id) {
        return service.find(id);
    }
}
