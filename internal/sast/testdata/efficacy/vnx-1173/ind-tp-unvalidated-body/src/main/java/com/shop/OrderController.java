package com.shop;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/orders")
public class OrderController {

    @PostMapping
    public Order create(@Valid @RequestBody OrderRequest req) {
        return service.create(req);
    }

    @PutMapping("/{id}")
    public Order update(@PathVariable Long id,
~>                        @RequestBody OrderRequest req) {
        return service.update(id, req);
    }
}
