package com.shop.web;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DiagnosticsController {

    @GetMapping("/diagnostics/env")
    public Map<String, String> env() {
~>        return System.getenv();
    }

    @GetMapping("/diagnostics/props")
    public ResponseEntity<?> props() {
~>        return ResponseEntity.ok(System.getProperties());
    }
}
