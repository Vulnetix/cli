package com.example;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {
    private final ScheduledExecutorService ticker = Executors.newScheduledThreadPool(1);
    private final ScheduledExecutorService single = Executors.newSingleThreadScheduledExecutor();
}
