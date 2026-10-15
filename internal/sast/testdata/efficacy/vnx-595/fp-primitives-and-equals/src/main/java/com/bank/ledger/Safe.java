package com.bank.ledger;

import java.math.BigDecimal;
import java.util.Objects;

public class Safe {
    boolean sameAccount(int fromId, int toId) {
        return fromId == toId;
    }

    boolean sameBoxed(Integer a, Integer b) {
        return Objects.equals(a, b) && a.equals(b);
    }

    boolean amounts(BigDecimal x, BigDecimal y) {
        return x.compareTo(y) == 0;
    }

    boolean count(long total, long expected) {
        long diff = total - expected;
        return diff == 0;
    }
}
