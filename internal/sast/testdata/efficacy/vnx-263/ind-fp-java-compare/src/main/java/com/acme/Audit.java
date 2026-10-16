package com.acme;

public class Audit {
    public boolean stale(User user) {
        // flag accounts whose password is older than a year
        return user.getPasswordAgeDays() > 365;
    }
}
