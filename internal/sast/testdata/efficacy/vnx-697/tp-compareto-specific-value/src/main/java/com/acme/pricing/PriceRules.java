package com.acme.pricing;

import java.math.BigDecimal;

public class PriceRules {

    public boolean overLimit(BigDecimal amount, BigDecimal limit) {
~>        return amount.compareTo(limit) == 1;
    }

    public boolean underFloor(String code, String floor) {
~>        if (code.compareToIgnoreCase(floor) == -1) {
            return true;
        }
~>        return code.compareTo(floor.trim())!=1;
    }
}
