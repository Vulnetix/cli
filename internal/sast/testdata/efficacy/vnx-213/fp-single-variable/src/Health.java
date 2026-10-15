package com.shop;

@RestController
public class Health {
    @GetMapping("/health")
    public String health() {
        return System.getenv("APP_VERSION");
    }
}
