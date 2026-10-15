package org.acme;

public class Guard {
    void check(User u) {
~>        if (!u.isAdmin());
        {
            throw new SecurityException("not admin");
        }
    }
}
