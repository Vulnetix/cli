package com.acme;

import java.security.MessageDigest;

class Old {
    byte[] h(byte[] b) throws Exception {
~>        return MessageDigest.getInstance("MD4").digest(b);
    }
}
