package com.acme;

import java.math.BigDecimal;

public class Limits {
    public boolean overLimit(BigDecimal amount, BigDecimal limit) {
~>        return amount.compareTo(limit) == 1;
    }
}
