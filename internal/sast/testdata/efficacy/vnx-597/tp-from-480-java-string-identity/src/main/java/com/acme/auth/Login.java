package com.acme.auth;

public class Login {
    boolean isAdmin(String role) {
~>        return role == "admin";
    }

    boolean check(User user, String token) {
~>        if ("expired" != user.getStatus() && token == "") {
            return true;
        }
        return false;
    }
}
