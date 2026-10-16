package com.acme.billing;

import java.math.BigDecimal;

public class Invoice {
    private BigDecimal total;

    public boolean isFree() {
~>        return total == BigDecimal.ZERO;
    }

    public boolean isSingleUnit(BigDecimal qty) {
~>        if (qty != BigDecimal.ONE) {
            return false;
        }
        return true;
    }
}
