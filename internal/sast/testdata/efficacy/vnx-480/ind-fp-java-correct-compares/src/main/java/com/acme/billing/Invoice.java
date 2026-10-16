package com.acme.billing;

import java.math.BigDecimal;

public class Invoice {
    private BigDecimal total;
    private String role;

    public boolean isFree() {
        return total.compareTo(BigDecimal.ZERO) == 0 || total.signum() == 0;
    }

    public boolean isAdmin() {
        return "admin".equals(role) && total != null;
    }

    public void credit(int n) {
        total = total.add(BigDecimal.valueOf(n));
        int delta = -n;
        delta += n;
    }
}
