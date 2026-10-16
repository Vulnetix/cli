package com.acme.sec;

import javax.crypto.Cipher;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.IDEAEngine;

public class OldSuites {
    Object cast() {
~>        return new CAST5Engine();
    }

    Object idea() {
~>        return new IDEAEngine();
    }

    Cipher ideaCipher() throws Exception {
~>        return Cipher.getInstance("IDEA/CBC/PKCS5Padding", "BC");
    }

    Cipher cast6() throws Exception {
        return Cipher.getInstance("CAST6/CBC/PKCS5Padding", "BC");
    }
}
