package com.acme;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    private final ScheduledExecutorService cacheRefresher = Executors.newScheduledThreadPool(1);
    private final ExecutorService auditWriter = Executors.newSingleThreadExecutor();

    public OrderController(OrderCache cache) {
        cacheRefresher.scheduleAtFixedRate(cache::refresh, 0, 5, TimeUnit.MINUTES);
    }

    @GetMapping("/orders/count")
    public long count(OrderCache cache) {
        auditWriter.submit(() -> Audit.log("count"));
        return cache.size();
    }
}
