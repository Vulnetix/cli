package com.acme.api;

import java.math.BigDecimal;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InvoiceController {
    private final InvoiceRepository repo;

    public InvoiceController(InvoiceRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/invoices/{invoiceId}")
    public Invoice get(@PathVariable String invoiceId) {
~>        return repo.findById(Long.parseLong(invoiceId)).orElseThrow();
    }

    @GetMapping("/invoices")
    public List<Invoice> search(@RequestParam("min") String minAmount,
                                @RequestParam(value = "limit", defaultValue = "50") String limit) {
~>        BigDecimal min = new BigDecimal(minAmount);
~>        int max = Integer.valueOf(limit);
        return repo.findByAmountGreaterThan(min, max);
    }
}
