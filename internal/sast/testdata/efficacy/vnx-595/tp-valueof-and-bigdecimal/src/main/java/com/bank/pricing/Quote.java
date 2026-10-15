package com.bank.pricing;

import java.math.BigDecimal;
import java.util.UUID;

public class Quote {
    private BigDecimal limit;

    boolean atLimit(BigDecimal amount) {
~>        return amount == limit;
    }

    boolean code(Integer status) {
~>        return status == Integer.valueOf(404);
    }

    boolean sameRequest(UUID first, UUID second) {
~>        return first.equals(second) || first == second;
    }
}
