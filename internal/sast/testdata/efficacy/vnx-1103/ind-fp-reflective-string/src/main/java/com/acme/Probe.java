package com.acme;

public class Probe {
    static boolean hasUnsafe() {
        try {
            Class.forName("sun.misc.Unsafe");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
    // historically we imported sun.misc.BASE64Encoder here
}
