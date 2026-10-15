package com.acme.web;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatsController {
    private int count;
    private final StatsService service;

    public StatsController(StatsService service) {
        this.service = service;
    }

    @GetMapping("/stats")
    public int stats() {
        List<Integer> xs = service.load();
        int total = 0;
        for (int count = 0; count < xs.size(); count++) {
            total += xs.get(count);
        }
        return total;
    }
}
