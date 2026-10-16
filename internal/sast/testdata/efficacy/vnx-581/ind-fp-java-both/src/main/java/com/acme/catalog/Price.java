package com.acme.catalog;

import java.math.BigDecimal;
import java.util.Objects;

public class Price {
    private final BigDecimal amount;
    private final String currency;

    public Price(BigDecimal amount, String currency) {
        this.amount = amount;
        this.currency = currency;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Price)) {
            return false;
        }
        Price p = (Price) o;
        return amount.compareTo(p.amount) == 0 && currency.equals(p.currency);
    }

    @Override
    public int hashCode() {
        return Objects.hash(amount.stripTrailingZeros(), currency);
    }
}
