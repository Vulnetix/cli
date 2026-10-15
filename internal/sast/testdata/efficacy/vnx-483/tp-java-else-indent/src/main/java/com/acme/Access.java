package com.acme;

public class Access {
    boolean grant(User user, Audit audit) {
        boolean ok = false;
        if (user.isAdmin())
            ok = true;
        else
            audit.deny(user);
~>            user.lock();
        return ok;
    }
}
