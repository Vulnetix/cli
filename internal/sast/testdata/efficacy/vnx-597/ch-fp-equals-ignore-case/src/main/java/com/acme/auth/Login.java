package com.acme.auth;

public class Login {
    boolean ok(String user, String pw) {
        String expected = "admin";
        if ("ADMIN".equalsIgnoreCase(user) || expected.equals(user)) {
            return pw != null && pw.length() > 0;
        }
        return user.compareTo("guest") == 0;
    }
}
