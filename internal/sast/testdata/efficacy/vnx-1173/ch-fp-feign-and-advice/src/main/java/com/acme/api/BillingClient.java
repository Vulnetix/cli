package com.acme.api;

import jakarta.validation.Valid;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "billing")
public interface BillingClient {

    @PostMapping("/invoices")
    Invoice create(@Valid @RequestBody InvoiceRequest req);

    @PostMapping("/refunds")
    Refund refund(@RequestBody RefundRequest req);
}
