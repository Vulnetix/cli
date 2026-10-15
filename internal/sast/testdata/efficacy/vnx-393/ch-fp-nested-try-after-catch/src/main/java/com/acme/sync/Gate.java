package com.acme.sync;

public class Gate {
    public boolean isNotAllowed(User u) {
        try {
            return !policy.permits(u);
        } catch (PolicyException e) {
            return true;
        }
    }

    public boolean isUserInvalid(User u) {
        try {
            return !validator.check(u);
        } catch (RuntimeException e) {
            return true;
        }
    }
}
