package com.acme.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    /**
     * Health summary.
     *
     * @deprecated callers should move to /actuator/health; kept for the load balancer.
     */
    @GetMapping("/status")
    public String status() {
        return "OK";
    }
}
