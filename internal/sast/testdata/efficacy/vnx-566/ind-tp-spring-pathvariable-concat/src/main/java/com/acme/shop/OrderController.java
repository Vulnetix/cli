package com.acme.shop;

import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    private final JdbcTemplate jdbc;

    public OrderController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/orders/{orderId}")
    public Map<String, Object> order(@PathVariable("orderId") String orderId) {
~>        return jdbc.queryForMap("SELECT total, shipping_address, status FROM orders WHERE order_id = " + orderId);
    }
}
