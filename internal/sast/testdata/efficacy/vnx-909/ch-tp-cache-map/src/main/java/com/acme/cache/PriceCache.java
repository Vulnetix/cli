package com.acme.cache;

import java.math.BigDecimal;
import java.util.Map;

public class PriceCache {
~>    private Map<String, BigDecimal> prices;

    public BigDecimal lookup(String sku) {
        return prices.get(sku);
    }

    public void put(String sku, BigDecimal price) {
        prices.put(sku, price);
    }
}
