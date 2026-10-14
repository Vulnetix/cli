package com.example.crypto;

public class Guide {
    // new IvParameterSpec("1234567890abcdef".getBytes()) reuses one IV for every message
    /*
     * private static final byte[] IV = {0, 0, 0, 0};
     */
    static final String NOTE = "never call new IvParameterSpec(new byte[16])";
    private static final int IV_SIZE = 16;
    private final String ivHeaderName = "X-IV";
}
