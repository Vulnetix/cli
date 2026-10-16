package com.acme;
import javax.crypto.Cipher;
public class Oaep {
    Cipher make() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
}
