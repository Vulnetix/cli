package org.example.billing;

import java.math.BigDecimal;

public class TaxTables {
~>    public static final BigDecimal RATES[];
~>    public static final String REGIONS[] = {
        "EU",
        "US",
        "APAC"
    };

    static {
        RATES = new BigDecimal[] {
            new BigDecimal("0.20"),
            new BigDecimal("0.07"),
            new BigDecimal("0.10")
        };
    }

    public BigDecimal rateFor(int idx) {
        return RATES[idx];
    }
}
