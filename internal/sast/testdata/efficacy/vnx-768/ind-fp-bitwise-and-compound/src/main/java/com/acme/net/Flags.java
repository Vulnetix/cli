package com.acme.net;

public class Flags {
    private static final int READ = 0x1;
    private static final int WRITE = 0x2;

    public boolean check(int mode, Object a, Object b) {
        int masked = mode & 0xFF;
        int combined = READ | WRITE;
        boolean ok = true;
        ok &= a != null;
        ok |= b != null;
        boolean both = (a != null) & (b != null);
        return both && (masked & combined) != 0 && ok;
    }
}
