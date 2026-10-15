package com.acme.io;

import java.io.File;

public class Stat {

    public long size(File f) {
        long len = f.length();
        return len;
    }

    public String human(File f) {
        return String.format("%d bytes (cast with (int) f.length() is unsafe)", f.length());
    }
}
