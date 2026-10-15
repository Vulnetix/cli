package org.acme;

public class Gate {
    boolean open(User u, boolean locked) {
        if (u == null) {
            return false;
~>        } else if (locked = false) {
            return true;
        }
        return u.isAdmin();
    }
}
