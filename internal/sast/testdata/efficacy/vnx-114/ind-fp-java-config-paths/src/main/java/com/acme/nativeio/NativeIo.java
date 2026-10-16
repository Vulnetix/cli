package com.acme.nativeio;

public final class NativeIo {
    static {
        System.loadLibrary("acme-native");
        String override = System.getProperty("acme.lib.path");
        if (override != null) {
            System.load(override);
        }
        String extra = System.getenv("ACME_EXTRA_LIB");
        if (extra != null) {
            Runtime.getRuntime().load(extra);
        }
    }

    private NativeIo() {}

    public static native int checksum(byte[] data);
}
