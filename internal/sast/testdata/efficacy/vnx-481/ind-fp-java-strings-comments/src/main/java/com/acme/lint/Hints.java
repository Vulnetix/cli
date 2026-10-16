package com.acme.lint;

public class Hints {
    // A common bug is writing if (x = y) instead of if (x == y).
    public String hint() {
        boolean ready = false;
        ready = check();
        if (ready == true) {
            return "write if (isAdmin == true), not if (isAdmin = true)";
        }
        return "";
    }

    private boolean check() { return true; }
}
