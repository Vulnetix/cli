package com.acme.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class TransferController {
    private final TransferService service;

    TransferController(TransferService service) {
        this.service = service;
    }

    @PostMapping("/transfers")
    public ResponseEntity<String> transfer(@RequestBody TransferRequest req) {
        try {
            service.transfer(req);
            return ResponseEntity.ok("done");
        } catch (InsufficientFundsException e) {
~>            return ResponseEntity.ok("transfer failed: " + e.getMessage());
        }
    }

    @DeleteMapping("/transfers/{id}")
    public ResponseEntity<Void> cancel(@PathVariable long id) {
        try {
            service.cancel(id);
        } catch (Exception e) {
            log.warn("cancel failed", e);
~>            return new ResponseEntity<>(HttpStatus.OK);
        }
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/transfers/{id}")
    public ResponseEntity<Transfer> get(@PathVariable long id) {
        try {
            return ResponseEntity.ok(service.find(id));
        } catch (RuntimeException e) {
~>            return ResponseEntity.status(HttpStatus.OK).body(null);
        }
    }
}
