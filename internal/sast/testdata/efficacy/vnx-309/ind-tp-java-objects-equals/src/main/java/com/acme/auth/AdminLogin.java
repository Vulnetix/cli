package com.acme.auth;

import java.util.Objects;

public class AdminLogin {
    public boolean check(AdminUser admin, String submittedPassword) {
~>        if (Objects.equals(submittedPassword, admin.getPassword())) {
            return true;
        }
        return false;
    }
}
