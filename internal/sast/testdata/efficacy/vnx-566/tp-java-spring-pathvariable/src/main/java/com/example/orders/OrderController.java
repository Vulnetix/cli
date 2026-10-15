package com.example.orders;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    private final JdbcTemplate jdbc;

    public OrderController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/orders/{orderId}")
    public Order get(@PathVariable("orderId") Long orderId) {
~>        return jdbc.queryForObject("SELECT id, total, status FROM orders WHERE id = ?",
                new OrderMapper(), orderId);
    }

    @GetMapping("/receipts")
    public Receipt receipt(@RequestParam final String receiptId) {
~>        return jdbc.queryForObject("SELECT * FROM receipts WHERE receipt_id = ?", new ReceiptMapper(), receiptId);
    }
}
