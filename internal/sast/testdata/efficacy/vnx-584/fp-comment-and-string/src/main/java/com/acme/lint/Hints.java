package com.acme.lint;

public class Hints {
    // } finally { return x; }
    private static final String MSG = "finally { return null; } discards exceptions";

    void ok() {
        try {
            work();
        } finally {
            String s = "return";
            release();
        }
    }
}
