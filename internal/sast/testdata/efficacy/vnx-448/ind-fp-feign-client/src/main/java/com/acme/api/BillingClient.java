package com.acme.api;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "billing", url = "${billing.url}")
public interface BillingClient {

    @Deprecated
    @GetMapping("/v1/invoices/{id}")
    InvoiceV1 getInvoiceV1(@PathVariable("id") String id);

    @GetMapping("/v2/invoices/{id}")
    Invoice getInvoice(@PathVariable("id") String id);
}
