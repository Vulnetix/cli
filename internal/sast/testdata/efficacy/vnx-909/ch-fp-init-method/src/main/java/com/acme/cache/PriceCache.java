package com.acme.cache;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;

public class PriceCache {
    private Map<String, BigDecimal> prices;

    public void init() {
        prices = new HashMap<>();
    }

    public BigDecimal lookup(String sku) {
        return prices.get(sku);
    }
}
