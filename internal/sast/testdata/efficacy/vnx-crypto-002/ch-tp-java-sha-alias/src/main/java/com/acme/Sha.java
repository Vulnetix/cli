package com.acme;

import java.security.MessageDigest;

public class Sha {
    byte[] d(byte[] b) throws Exception {
~>        MessageDigest md = MessageDigest.getInstance("SHA");
        return md.digest(b);
    }
}
