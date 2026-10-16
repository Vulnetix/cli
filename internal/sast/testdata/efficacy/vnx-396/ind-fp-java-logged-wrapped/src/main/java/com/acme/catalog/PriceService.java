package com.acme.catalog;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PriceService {
    private static final Logger log = LoggerFactory.getLogger(PriceService.class);
    private final PriceClient client;

    public PriceService(PriceClient client) {
        this.client = client;
    }

    public Price current(String sku) {
        try {
            return client.fetch(sku);
        } catch (Exception e) {
            log.error("price lookup failed for {}", sku, e);
            return null;
        }
    }

    public Price strict(String sku) {
        try {
            return client.fetch(sku);
        } catch (RuntimeException e) {
            throw new PricingException("price lookup failed for " + sku, e);
        }
    }
}
