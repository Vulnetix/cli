package com.acme.billing;

import java.math.BigDecimal;

public class Invoice {
    boolean free(BigDecimal total) {
~>        return total == BigDecimal.ZERO;
    }

    boolean unit(BigDecimal qty) {
~>        if (BigDecimal.ONE != qty) {
            return false;
        }
        return true;
    }
}
