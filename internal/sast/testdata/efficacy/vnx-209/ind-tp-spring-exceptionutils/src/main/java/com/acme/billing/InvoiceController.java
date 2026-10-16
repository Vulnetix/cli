package com.acme.billing;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InvoiceController {

    private final InvoiceService invoices;

    public InvoiceController(InvoiceService invoices) {
        this.invoices = invoices;
    }

    @GetMapping("/invoices/{id}")
    public ResponseEntity<?> get(@PathVariable long id) {
        try {
            return ResponseEntity.ok(invoices.find(id));
        } catch (RuntimeException e) {
~>            return ResponseEntity.status(500).body(ExceptionUtils.getStackTrace(e));
        }
    }
}
