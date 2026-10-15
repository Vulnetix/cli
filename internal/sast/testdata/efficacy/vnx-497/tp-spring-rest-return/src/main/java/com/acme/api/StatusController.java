package com.acme.api;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {
    @GetMapping("/status/home")
    public String home() {
~>        return System.getProperty("user.home");
    }

    @GetMapping("/status/env")
    public ResponseEntity<Map<String, String>> env() {
~>        return ResponseEntity.ok(System.getenv());
    }

    @GetMapping("/status/runtime")
    public Map<String, String> runtime() {
        String classpath = System.getProperty("java.class.path");
~>        return Map.of("classpath", classpath);
    }
}
