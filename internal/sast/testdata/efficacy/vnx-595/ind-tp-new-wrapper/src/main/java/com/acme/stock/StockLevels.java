package com.acme.stock;

import java.util.Map;

public class StockLevels {

    private final Map<String, Long> onHand;

    public StockLevels(Map<String, Long> onHand) {
        this.onHand = onHand;
    }

    public boolean isSoldOut(String sku) {
        Object level = onHand.get(sku);
~>        return level == new Long(0L);
    }
}
