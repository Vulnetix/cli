package com.acme;

import java.io.File;

public class Copy {
    byte[] prepare(File source) {
        long size = source.length();
        log("size " + size);
~>        return new byte[(int) size];
    }
}
