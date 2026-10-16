package com.acme;
import javax.crypto.spec.SecretKeySpec;
public class Crypt {
    Object key() {
~>        return new SecretKeySpec("mysecretkey12345".getBytes(), "AES");
    }
}
