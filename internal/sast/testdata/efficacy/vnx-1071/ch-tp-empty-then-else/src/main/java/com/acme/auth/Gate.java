package com.acme.auth;

public class Gate {
    public boolean allow(User user, Resource r) {
~>        if (user.isAdmin()) { } else { audit(user, r); }
        if (r.isLocked()) {
            return false;
~>        } else if (r.isPublic()) {
        }
        return r.owner().equals(user);
    }

    private void audit(User u, Resource r) {
        System.out.println(u + " " + r);
    }
}
