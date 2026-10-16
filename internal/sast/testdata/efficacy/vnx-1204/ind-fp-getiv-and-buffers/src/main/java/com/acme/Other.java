package com.acme;

import java.io.InputStream;
import javax.crypto.Cipher;

public class Other {
    byte[] header(Cipher c) {
        return c.getIV();
    }

    int slurp(InputStream in) throws Exception {
        byte[] buf = new byte[8192];
        return in.read(buf);
    }

    // new IvParameterSpec(new byte[16]) would be a bug
    String doc = "new IvParameterSpec(new byte[16])";
}
