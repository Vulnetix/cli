package com.acme.api;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

~>@Deprecated
@RestController
@RequestMapping("/api/v1/orders")
public class OrdersV1Controller {

    private final OrderService orders;

    public OrdersV1Controller(OrderService orders) {
        this.orders = orders;
    }

    @GetMapping
    public List<OrderV1> list() {
        return orders.listAllV1();
    }
}
