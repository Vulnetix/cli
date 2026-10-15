package com.acme.net;

public class Flags {
    private static final String HINT = "x != null & x.size() is a bug";

    public int low(int value, Integer mask) {
        int r = value & 0xff;
        // if (mask != null & mask.intValue() > 0) was wrong, fixed below
        if (mask != null && (mask.intValue() & r) != 0) {
            return r;
        }
        return value | r;
    }
}
