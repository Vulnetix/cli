package com.acme;

public class Gate {
    public boolean allow(User u) {
~>        if (u.isAdmin()) {}
        if (u.isBlocked()) {
            return false;
~>        } else {
        }
~>        if (u.getRole() == null) {
        }
        return true;
    }
}
