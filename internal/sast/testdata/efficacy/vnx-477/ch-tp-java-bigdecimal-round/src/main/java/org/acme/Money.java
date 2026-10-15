package org.acme;

import java.math.BigDecimal;

public class Money {
    BigDecimal round(BigDecimal v) {
~>        return v.setScale(2, BigDecimal.ROUND_HALF_UP);
    }

    BigDecimal share(BigDecimal total, BigDecimal parts) {
~>        return total.divide(parts, BigDecimal.ROUND_DOWN);
    }
}
