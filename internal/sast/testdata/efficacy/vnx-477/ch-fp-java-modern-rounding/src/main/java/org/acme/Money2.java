package org.acme;

import java.math.BigDecimal;
import java.math.RoundingMode;

public class Money2 {
    // BigDecimal.ROUND_HALF_UP was replaced by RoundingMode.HALF_UP
    BigDecimal round(BigDecimal v) {
        return v.setScale(2, RoundingMode.HALF_UP);
    }

    String doc() {
        return "avoid BigDecimal.ROUND_DOWN";
    }
}
