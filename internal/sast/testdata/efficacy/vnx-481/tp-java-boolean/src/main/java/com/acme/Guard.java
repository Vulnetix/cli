package com.acme;

public class Guard {
    private boolean isAdmin;

    String page(boolean admin) {
~>        if (isAdmin = true) {
            return "admin";
        }
~>        while (this.isAdmin = admin) {
            break;
        }
        return "user";
    }
}
