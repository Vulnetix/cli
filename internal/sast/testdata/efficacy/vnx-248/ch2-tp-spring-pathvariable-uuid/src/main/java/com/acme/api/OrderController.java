package com.acme.api;

import java.util.UUID;
import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {
    @GetMapping("/orders/{id}")
    public Order get(@PathVariable("id") String id) {
~>        return repo.find(UUID.fromString(id));
    }
}
