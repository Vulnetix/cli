package com.acme.accounts;

import java.math.BigDecimal;
import java.util.Objects;

public class OwnershipCheck {

    public boolean isOwner(Integer ownerId, Integer requesterId) {
        return Objects.equals(ownerId, requesterId);
    }

    public boolean sameAmount(BigDecimal a, BigDecimal b) {
        return a.compareTo(b) == 0;
    }

    public boolean sameUser(Long left, Long right) {
        return left != null && left.equals(right);
    }
}
