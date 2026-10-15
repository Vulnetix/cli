package com.acme;

import java.math.BigDecimal;

public class Roles {
    boolean isAdmin(String role, char c, BigDecimal total, int n) {
        int delta = -n;
        int offset = n;
        offset = -delta;
        offset -= 1;
        if (role == null || c == 'a') {
            return false;
        }
        return "admin".equals(role) && total.compareTo(BigDecimal.ZERO) == 0 && offset != 0;
    }
}
