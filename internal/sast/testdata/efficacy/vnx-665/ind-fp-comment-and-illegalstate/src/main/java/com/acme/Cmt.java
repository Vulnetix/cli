package com.acme;

public class Cmt {
    static String NAME;

    static {
        try {
            NAME = lookup();
        } catch (Exception e) {
            throw new IllegalStateException("lookup failed", e);
        }
        // } catch (Exception e) {
        // }
    }

    static String lookup() { return "x"; }
}
