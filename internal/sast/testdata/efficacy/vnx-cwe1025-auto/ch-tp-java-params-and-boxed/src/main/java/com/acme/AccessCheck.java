package com.acme;

import java.util.Map;

public class AccessCheck {

    private static final String ADMIN_ROLE = "admin";

    public boolean sameUser(String expected, String actual) {
~>        return expected == actual;
    }

    public boolean isAdmin(javax.servlet.http.HttpServletRequest request) {
        String role = request.getHeader("X-Role");
~>        if (role != ADMIN_ROLE) {
            return false;
        }
        return true;
    }

    public boolean sameQuota(Map<String, Long> quotas, String a, String b) {
        Long first = quotas.get(a);
        Long second = quotas.get(b);
~>        return first == second;
    }
}
