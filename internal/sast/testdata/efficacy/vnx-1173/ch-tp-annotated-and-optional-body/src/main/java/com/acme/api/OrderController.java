package com.acme.api;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/orders")
public class OrderController {

    @PostMapping
    public OrderDto create(@Valid @RequestBody CreateOrder body) {
        return service.create(body);
    }

    @PatchMapping("/{id}")
~>    public OrderDto patch(@PathVariable long id, @RequestBody(required = false) PatchOrder patch) {
        return service.patch(id, patch);
    }

    @PutMapping("/{id}")
~>    public OrderDto replace(@PathVariable long id, @RequestBody @NotNull ReplaceOrder body) {
        return service.replace(id, body);
    }

    @PostMapping("/bulk")
    public void bulk(
~>            @RequestBody List<CreateOrder> orders) {
        service.bulk(orders);
    }
}
