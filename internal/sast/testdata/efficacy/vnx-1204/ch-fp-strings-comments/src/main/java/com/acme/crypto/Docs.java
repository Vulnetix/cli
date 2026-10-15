package com.acme.crypto;

import javax.crypto.spec.IvParameterSpec;

public class Docs {
    // Never do: new IvParameterSpec(new byte[16])
    /*
     * byte[] iv = {0, 0, 0, 0}; new IvParameterSpec(iv) repeats the IV.
     */
    public static final String WARNING = "new IvParameterSpec(new byte[16]) is insecure";

    public IvParameterSpec of(byte[] iv) {
        return new IvParameterSpec(iv);
    }
}
