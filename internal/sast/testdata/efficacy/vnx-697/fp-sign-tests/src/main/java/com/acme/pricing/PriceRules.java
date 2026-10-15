package com.acme.pricing;

import java.math.BigDecimal;

public class PriceRules {
    public boolean overLimit(BigDecimal amount, BigDecimal limit) {
        return amount.compareTo(limit) > 0;
    }

    public boolean same(BigDecimal a, BigDecimal b) {
        return a.compareTo(b) == 0 || a.compareTo(b) >= 1 || a.compareTo(b) == 10;
    }

    public int count(java.util.List<String> xs) {
        return xs.size() == 1 ? 1 : 0;
    }
}
