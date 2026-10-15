package com.example.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "billing")
public interface BillingClient {

    @Deprecated
    @GetMapping("/v1/invoices/{id}")
    Invoice invoiceV1(@PathVariable("id") String id);

    @GetMapping("/v2/invoices/{id}")
    Invoice invoice(@PathVariable("id") String id);
}
