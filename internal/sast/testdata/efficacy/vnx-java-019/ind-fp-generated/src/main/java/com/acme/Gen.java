package com.acme;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
public class Gen {
    SecretKey make() throws Exception {
        KeyGenerator g = KeyGenerator.getInstance("AES");
        g.init(256);
        // new SecretKeySpec("abcdefabcdefabcd".getBytes(), "AES")
        return g.generateKey();
    }
}
