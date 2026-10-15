package com.acme.ledger;

import java.util.Objects;

public class Match {
    boolean match(Long a, Long b) {
        if (a == null || b == null) {
            return false;
        }
        return Objects.equals(a, b) && a.longValue() == b.longValue();
    }
}
