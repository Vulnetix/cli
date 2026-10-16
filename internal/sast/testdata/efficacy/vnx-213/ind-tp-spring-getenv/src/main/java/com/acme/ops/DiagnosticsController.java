package com.acme.ops;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DiagnosticsController {

    @GetMapping("/internal/env")
    public ResponseEntity<Map<String, String>> env() {
~>        return ResponseEntity.ok(System.getenv());
    }
}
