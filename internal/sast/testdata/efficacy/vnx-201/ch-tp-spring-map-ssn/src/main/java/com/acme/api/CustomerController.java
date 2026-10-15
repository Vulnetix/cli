package com.acme.api;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class CustomerController {
    private final CustomerRepository repo;

    CustomerController(CustomerRepository repo) { this.repo = repo; }

    @GetMapping("/customers/{id}")
    public ResponseEntity<Map<String, String>> get(@PathVariable long id) {
        Customer customer = repo.findById(id).orElseThrow();
~>        return ResponseEntity.ok(Map.of("name", customer.getName(), "ssn", customer.getSsn()));
    }
}
