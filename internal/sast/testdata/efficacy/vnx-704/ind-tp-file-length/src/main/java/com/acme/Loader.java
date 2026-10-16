package com.acme;

import java.io.File;

public class Loader {
    byte[] alloc(File file) {
~>        byte[] buf = new byte[(int) file.length()];
        return buf;
    }
}
