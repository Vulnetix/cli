package com.acme.orders;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    private final JdbcTemplate jdbcTemplate;

    public OrderController(JdbcTemplate jdbcTemplate) { this.jdbcTemplate = jdbcTemplate; }

    @GetMapping("/orders")
    public List<Map<String, Object>> byStatus(@RequestParam(value = "status", defaultValue = "OPEN") String status) {
~>        return jdbcTemplate.queryForList("SELECT * FROM orders WHERE status = '" + status + "'");
    }
}
