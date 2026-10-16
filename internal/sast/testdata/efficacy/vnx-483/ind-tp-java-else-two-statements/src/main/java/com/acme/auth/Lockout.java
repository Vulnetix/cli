package com.acme.auth;

public class Lockout {
    public void onFailure(User user, Audit audit) {
        if (user.failures() < 5)
            audit.warn(user);
        else
            audit.deny(user);
~>            user.lock();
    }
}
