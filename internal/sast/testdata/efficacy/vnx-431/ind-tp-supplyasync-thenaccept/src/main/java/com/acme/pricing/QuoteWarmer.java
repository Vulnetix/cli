package com.acme.pricing;

import java.util.List;
import java.util.concurrent.CompletableFuture;

public class QuoteWarmer {
    private final PricingClient pricing;
    private final QuoteCache cache;

    QuoteWarmer(PricingClient pricing, QuoteCache cache) {
        this.pricing = pricing;
        this.cache = cache;
    }

    public void warm(List<String> skus) {
        for (String sku : skus) {
~>            CompletableFuture.supplyAsync(() -> pricing.quote(sku)).thenAccept(cache::put);
        }
    }
}
